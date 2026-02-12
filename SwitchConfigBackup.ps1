#Requires -Version 5.0
<#
.SYNOPSIS
    Switch Config Backup Tool - GUI application for backing up Hirschmann and Cisco switch configurations.
.DESCRIPTION
    Uses PuTTY plink.exe for SSH connections. Scans subnets, identifies switch vendors,
    downloads and cleans running configurations, saves to files.
.NOTES
    Launch: powershell -ExecutionPolicy Bypass -File SwitchConfigBackup.ps1
#>

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

# ---------------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------------

function ConvertFrom-CIDR {
    param([string]$CIDR)
    $parts = $CIDR.Trim() -split '/'
    if ($parts.Count -ne 2) { return @() }
    $ipStr = $parts[0]
    $prefix = [int]$parts[1]
    if ($prefix -lt 1 -or $prefix -gt 30) { return @() }

    $ipBytes = ([System.Net.IPAddress]::Parse($ipStr)).GetAddressBytes()
    [Array]::Reverse($ipBytes)
    $ipUint = [BitConverter]::ToUInt32($ipBytes, 0)

    $maskBits = ([uint32]([Math]::Pow(2, 32) - 1)) -shl (32 - $prefix)
    $network = $ipUint -band $maskBits
    $broadcast = $network -bor (-bnot $maskBits -band 0xFFFFFFFF)

    $ips = @()
    for ($i = $network + 1; $i -lt $broadcast; $i++) {
        $bytes = [BitConverter]::GetBytes([uint32]$i)
        [Array]::Reverse($bytes)
        $ips += ([System.Net.IPAddress]::new($bytes)).ToString()
    }
    return $ips
}

function Test-TCPPort {
    param([string]$IP, [int]$Port = 22, [int]$Timeout = 1000)
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $ar = $client.BeginConnect($IP, $Port, $null, $null)
        $waited = $ar.AsyncWaitHandle.WaitOne($Timeout, $false)
        if ($waited -and $client.Connected) {
            $client.EndConnect($ar)
            $client.Close()
            return $true
        }
        $client.Close()
        return $false
    } catch {
        return $false
    }
}

function Find-Plink {
    # Search common locations for plink.exe
    $candidates = @(
        (Get-Command plink.exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -ErrorAction SilentlyContinue),
        "$env:ProgramFiles\PuTTY\plink.exe",
        "${env:ProgramFiles(x86)}\PuTTY\plink.exe",
        "$env:USERPROFILE\Desktop\plink.exe",
        "$env:USERPROFILE\Downloads\plink.exe",
        ".\plink.exe"
    )
    foreach ($p in $candidates) {
        if ($p -and (Test-Path $p -ErrorAction SilentlyContinue)) { return $p }
    }
    return $null
}

function Sanitize-Filename {
    param([string]$Name)
    if (-not $Name) { return "unknown" }
    $Name = $Name -replace '/', '-'
    $invalid = [IO.Path]::GetInvalidFileNameChars() -join ''
    $regex = "[{0}]" -f [regex]::Escape($invalid)
    $Name = $Name -replace $regex, '_'
    $Name = $Name.Trim('_').Trim()
    if (-not $Name) { return "unknown" }
    return $Name
}

# ---------------------------------------------------------------------------
# SNMP v2c Helper Functions (Pure PowerShell - raw UDP + BER/ASN.1)
# ---------------------------------------------------------------------------

function ConvertTo-BerLength {
    param([int]$Length)
    if ($Length -lt 128) {
        return [byte[]]@([byte]$Length)
    } elseif ($Length -lt 256) {
        return [byte[]]@(0x81, [byte]$Length)
    } elseif ($Length -lt 65536) {
        $b1 = [byte](($Length -shr 8) -band 0xFF)
        $b2 = [byte]($Length -band 0xFF)
        return [byte[]]@(0x82, $b1, $b2)
    } else {
        $b1 = [byte](($Length -shr 16) -band 0xFF)
        $b2 = [byte](($Length -shr 8) -band 0xFF)
        $b3 = [byte]($Length -band 0xFF)
        return [byte[]]@(0x83, $b1, $b2, $b3)
    }
}

function ConvertTo-BerOid {
    param([string]$OidString)
    $parts = $OidString.Trim('.') -split '\.' | ForEach-Object { [int]$_ }
    if ($parts.Count -lt 2) { return [byte[]]@() }
    $bytes = [System.Collections.ArrayList]::new()
    [void]$bytes.Add([byte](40 * $parts[0] + $parts[1]))
    for ($i = 2; $i -lt $parts.Count; $i++) {
        $val = $parts[$i]
        if ($val -lt 128) {
            [void]$bytes.Add([byte]$val)
        } else {
            $encoded = [System.Collections.ArrayList]::new()
            [void]$encoded.Add([byte]($val -band 0x7F))
            $val = $val -shr 7
            while ($val -gt 0) {
                [void]$encoded.Insert(0, [byte](($val -band 0x7F) -bor 0x80))
                $val = $val -shr 7
            }
            foreach ($b in $encoded) { [void]$bytes.Add($b) }
        }
    }
    $oidBytes = [byte[]]$bytes.ToArray()
    $lenBytes = ConvertTo-BerLength -Length $oidBytes.Count
    $result = [byte[]]@(0x06) + $lenBytes + $oidBytes
    return $result
}

function ConvertFrom-BerOid {
    param([byte[]]$Bytes)
    if ($Bytes.Count -eq 0) { return "" }
    $parts = [System.Collections.ArrayList]::new()
    [void]$parts.Add([Math]::Floor($Bytes[0] / 40))
    [void]$parts.Add($Bytes[0] % 40)
    $i = 1
    while ($i -lt $Bytes.Count) {
        $val = 0
        while ($i -lt $Bytes.Count) {
            $b = $Bytes[$i]; $i++
            $val = ($val -shl 7) -bor ($b -band 0x7F)
            if (($b -band 0x80) -eq 0) { break }
        }
        [void]$parts.Add($val)
    }
    return ($parts -join '.')
}

function Build-BerSequence {
    param([byte[]]$Content)
    $lenBytes = ConvertTo-BerLength -Length $Content.Count
    return [byte[]]@(0x30) + $lenBytes + $Content
}

function Build-BerInteger {
    param([int]$Value)
    if ($Value -ge 0 -and $Value -lt 128) {
        return [byte[]]@(0x02, 0x01, [byte]$Value)
    } elseif ($Value -ge 128 -and $Value -lt 256) {
        return [byte[]]@(0x02, 0x02, 0x00, [byte]$Value)
    } elseif ($Value -ge 256 -and $Value -lt 32768) {
        $hi = [byte](($Value -shr 8) -band 0xFF)
        $lo = [byte]($Value -band 0xFF)
        return [byte[]]@(0x02, 0x02, $hi, $lo)
    } elseif ($Value -ge 32768 -and $Value -lt 65536) {
        $hi = [byte](($Value -shr 8) -band 0xFF)
        $lo = [byte]($Value -band 0xFF)
        return [byte[]]@(0x02, 0x03, 0x00, $hi, $lo)
    } else {
        $b4 = [byte]($Value -band 0xFF)
        $b3 = [byte](($Value -shr 8) -band 0xFF)
        $b2 = [byte](($Value -shr 16) -band 0xFF)
        $b1 = [byte](($Value -shr 24) -band 0xFF)
        if ($b1 -ge 128) {
            return [byte[]]@(0x02, 0x05, 0x00, $b1, $b2, $b3, $b4)
        }
        return [byte[]]@(0x02, 0x04, $b1, $b2, $b3, $b4)
    }
}

function Build-BerOctetString {
    param([string]$Value)
    $strBytes = [System.Text.Encoding]::ASCII.GetBytes($Value)
    $lenBytes = ConvertTo-BerLength -Length $strBytes.Count
    return [byte[]]@(0x04) + $lenBytes + $strBytes
}

function Build-BerNull {
    return [byte[]]@(0x05, 0x00)
}

function Build-BerIpAddress {
    param([string]$IP)
    $parts = $IP -split '\.' | ForEach-Object { [byte]$_ }
    return [byte[]]@(0x40, 0x04) + [byte[]]$parts
}

function Build-SnmpVarbind {
    param([string]$Oid, [byte[]]$ValueTlv = $null)
    $oidTlv = ConvertTo-BerOid -OidString $Oid
    if (-not $ValueTlv) { $ValueTlv = Build-BerNull }
    $varbindContent = $oidTlv + $ValueTlv
    return Build-BerSequence -Content $varbindContent
}

function Build-SnmpGetRequest {
    param(
        [string]$Community = "public",
        [string[]]$Oids,
        [int]$RequestId = 1
    )
    $varbinds = [byte[]]@()
    foreach ($oid in $Oids) {
        $varbinds += Build-SnmpVarbind -Oid $oid
    }
    $varbindList = Build-BerSequence -Content $varbinds

    $reqIdBer = Build-BerInteger -Value $RequestId
    $errorStatusBer = Build-BerInteger -Value 0
    $errorIndexBer = Build-BerInteger -Value 0
    $pduContent = $reqIdBer + $errorStatusBer + $errorIndexBer + $varbindList
    $pduLenBytes = ConvertTo-BerLength -Length $pduContent.Count
    $pdu = [byte[]]@(0xA0) + $pduLenBytes + $pduContent  # 0xA0 = GetRequest

    $versionBer = Build-BerInteger -Value 1  # SNMPv2c
    $communityBer = Build-BerOctetString -Value $Community
    $messageContent = $versionBer + $communityBer + $pdu
    return Build-BerSequence -Content $messageContent
}

function Build-SnmpGetNextRequest {
    param(
        [string]$Community = "public",
        [string[]]$Oids,
        [int]$RequestId = 1
    )
    $varbinds = [byte[]]@()
    foreach ($oid in $Oids) {
        $varbinds += Build-SnmpVarbind -Oid $oid
    }
    $varbindList = Build-BerSequence -Content $varbinds

    $reqIdBer = Build-BerInteger -Value $RequestId
    $errorStatusBer = Build-BerInteger -Value 0
    $errorIndexBer = Build-BerInteger -Value 0
    $pduContent = $reqIdBer + $errorStatusBer + $errorIndexBer + $varbindList
    $pduLenBytes = ConvertTo-BerLength -Length $pduContent.Count
    $pdu = [byte[]]@(0xA1) + $pduLenBytes + $pduContent  # 0xA1 = GetNextRequest

    $versionBer = Build-BerInteger -Value 1
    $communityBer = Build-BerOctetString -Value $Community
    $messageContent = $versionBer + $communityBer + $pdu
    return Build-BerSequence -Content $messageContent
}

function Build-SnmpSetRequest {
    param(
        [string]$Community = "private",
        [string]$Oid,
        [byte[]]$ValueTlv,
        [int]$RequestId = 1
    )
    $varbind = Build-SnmpVarbind -Oid $Oid -ValueTlv $ValueTlv
    $varbindList = Build-BerSequence -Content $varbind

    $reqIdBer = Build-BerInteger -Value $RequestId
    $errorStatusBer = Build-BerInteger -Value 0
    $errorIndexBer = Build-BerInteger -Value 0
    $pduContent = $reqIdBer + $errorStatusBer + $errorIndexBer + $varbindList
    $pduLenBytes = ConvertTo-BerLength -Length $pduContent.Count
    $pdu = [byte[]]@(0xA3) + $pduLenBytes + $pduContent  # 0xA3 = SetRequest

    $versionBer = Build-BerInteger -Value 1
    $communityBer = Build-BerOctetString -Value $Community
    $messageContent = $versionBer + $communityBer + $pdu
    return Build-BerSequence -Content $messageContent
}

function Read-BerLength {
    param([byte[]]$Data, [int]$Offset)
    if ($Offset -ge $Data.Count) { return @{ Length = 0; BytesConsumed = 0 } }
    $firstByte = $Data[$Offset]
    if ($firstByte -lt 128) {
        return @{ Length = [int]$firstByte; BytesConsumed = 1 }
    }
    $numLenBytes = $firstByte -band 0x7F
    $length = 0
    for ($i = 0; $i -lt $numLenBytes; $i++) {
        $length = ($length -shl 8) + $Data[$Offset + 1 + $i]
    }
    return @{ Length = $length; BytesConsumed = 1 + $numLenBytes }
}

function Parse-SnmpResponse {
    param([byte[]]$Data)
    try {
        if ($Data.Count -lt 2 -or $Data[0] -ne 0x30) { return $null }
        $pos = 1
        $seqLen = Read-BerLength -Data $Data -Offset $pos
        $pos += $seqLen.BytesConsumed

        # Version
        if ($Data[$pos] -ne 0x02) { return $null }
        $pos++
        $verLen = Read-BerLength -Data $Data -Offset $pos
        $pos += $verLen.BytesConsumed + $verLen.Length

        # Community
        if ($Data[$pos] -ne 0x04) { return $null }
        $pos++
        $comLen = Read-BerLength -Data $Data -Offset $pos
        $pos += $comLen.BytesConsumed
        $community = [System.Text.Encoding]::ASCII.GetString($Data, $pos, $comLen.Length)
        $pos += $comLen.Length

        # PDU (0xA2 = GetResponse)
        $pduTag = $Data[$pos]
        $pos++
        $pduLen = Read-BerLength -Data $Data -Offset $pos
        $pos += $pduLen.BytesConsumed

        # Request ID
        $pos++
        $ridLen = Read-BerLength -Data $Data -Offset $pos
        $pos += $ridLen.BytesConsumed
        $requestId = 0
        for ($i = 0; $i -lt $ridLen.Length; $i++) {
            $requestId = ($requestId -shl 8) + $Data[$pos + $i]
        }
        $pos += $ridLen.Length

        # Error Status
        $pos++
        $esLen = Read-BerLength -Data $Data -Offset $pos
        $pos += $esLen.BytesConsumed
        $errorStatus = 0
        for ($i = 0; $i -lt $esLen.Length; $i++) {
            $errorStatus = ($errorStatus -shl 8) + $Data[$pos + $i]
        }
        $pos += $esLen.Length

        # Error Index
        $pos++
        $eiLen = Read-BerLength -Data $Data -Offset $pos
        $pos += $eiLen.BytesConsumed
        $pos += $eiLen.Length

        # Varbind List (SEQUENCE)
        if ($Data[$pos] -ne 0x30) { return $null }
        $pos++
        $vblLen = Read-BerLength -Data $Data -Offset $pos
        $pos += $vblLen.BytesConsumed
        $vblEnd = $pos + $vblLen.Length

        $results = @{}
        while ($pos -lt $vblEnd -and $pos -lt $Data.Count) {
            # Each varbind is a SEQUENCE
            if ($Data[$pos] -ne 0x30) { break }
            $pos++
            $vbLen = Read-BerLength -Data $Data -Offset $pos
            $pos += $vbLen.BytesConsumed
            $vbEnd = $pos + $vbLen.Length

            # OID
            if ($Data[$pos] -ne 0x06) { break }
            $pos++
            $oidLen = Read-BerLength -Data $Data -Offset $pos
            $pos += $oidLen.BytesConsumed
            $oidBytes = $Data[$pos..($pos + $oidLen.Length - 1)]
            $oid = ConvertFrom-BerOid -Bytes $oidBytes
            $pos += $oidLen.Length

            # Value
            $valueTag = $Data[$pos]
            $pos++
            $valLen = Read-BerLength -Data $Data -Offset $pos
            $pos += $valLen.BytesConsumed
            $valueBytes = if ($valLen.Length -gt 0) { $Data[$pos..($pos + $valLen.Length - 1)] } else { @() }

            $value = $null
            switch ($valueTag) {
                0x02 { # INTEGER
                    $intVal = 0
                    foreach ($b in $valueBytes) { $intVal = ($intVal -shl 8) + $b }
                    $value = $intVal
                }
                0x04 { # OCTET STRING
                    # OID-aware decoding for known HiDiscovery binary fields
                    if ($oid -eq "1.3.6.1.4.1.248.16.100.1.2.0" -and $valueBytes.Count -eq 6) {
                        # MAC address: always format as hex
                        $value = ($valueBytes | ForEach-Object { $_.ToString("X2") }) -join ':'
                    } elseif (($oid -eq "1.3.6.1.4.1.248.16.100.2.4.0" -or $oid -eq "1.3.6.1.4.1.248.16.100.2.7.0") -and $valueBytes.Count -eq 4) {
                        # IP Address / Gateway returned as OCTET STRING: format as dotted decimal
                        $value = "$($valueBytes[0]).$($valueBytes[1]).$($valueBytes[2]).$($valueBytes[3])"
                    } else {
                        $isPrintable = $true
                        foreach ($b in $valueBytes) {
                            if (($b -lt 0x20 -and $b -ne 0x0A -and $b -ne 0x0D -and $b -ne 0x09) -or $b -gt 0x7E) {
                                $isPrintable = $false; break
                            }
                        }
                        if ($isPrintable -and $valueBytes.Count -gt 0) {
                            $value = [System.Text.Encoding]::ASCII.GetString([byte[]]$valueBytes)
                        } else {
                            $value = ($valueBytes | ForEach-Object { $_.ToString("X2") }) -join ':'
                        }
                    }
                }
                0x05 { $value = $null }  # NULL
                0x06 { $value = ConvertFrom-BerOid -Bytes ([byte[]]$valueBytes) }  # OID
                0x40 { # IpAddress
                    if ($valueBytes.Count -eq 4) {
                        $value = "$($valueBytes[0]).$($valueBytes[1]).$($valueBytes[2]).$($valueBytes[3])"
                    } else {
                        $value = ($valueBytes | ForEach-Object { $_.ToString("X2") }) -join ':'
                    }
                }
                0x41 { # Counter32
                    $intVal = [uint32]0
                    foreach ($b in $valueBytes) { $intVal = ($intVal -shl 8) + $b }
                    $value = $intVal
                }
                0x42 { # Gauge32 / Unsigned32
                    $intVal = [uint32]0
                    foreach ($b in $valueBytes) { $intVal = ($intVal -shl 8) + $b }
                    $value = $intVal
                }
                0x43 { # TimeTicks
                    $intVal = [uint32]0
                    foreach ($b in $valueBytes) { $intVal = ($intVal -shl 8) + $b }
                    $value = $intVal
                }
                0x80 { $value = "noSuchObject" }
                0x81 { $value = "noSuchInstance" }
                0x82 { $value = "endOfMibView" }
                default {
                    $value = ($valueBytes | ForEach-Object { $_.ToString("X2") }) -join ':'
                }
            }
            $results[$oid] = @{ Value = $value; Tag = $valueTag; Raw = [byte[]]$valueBytes }
            $pos = $vbEnd
        }
        return @{ ErrorStatus = $errorStatus; RequestId = $requestId; Results = $results }
    } catch {
        return $null
    }
}

function Send-SnmpRequest {
    param(
        [string]$IP,
        [byte[]]$Packet,
        [int]$Port = 161,
        [int]$TimeoutMs = 2000
    )
    try {
        $udp = New-Object System.Net.Sockets.UdpClient
        $udp.Client.ReceiveTimeout = $TimeoutMs
        $udp.Client.SendTimeout = $TimeoutMs
        $endpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($IP), $Port)
        [void]$udp.Send($Packet, $Packet.Length, $endpoint)
        $remoteEP = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        $response = $udp.Receive([ref]$remoteEP)
        $udp.Close()
        return $response
    } catch {
        if ($udp) { try { $udp.Close() } catch {} }
        return $null
    }
}

function Invoke-SnmpGet {
    param(
        [string]$IP,
        [string[]]$Oids,
        [string]$Community = "public",
        [int]$TimeoutMs = 2000
    )
    $requestId = Get-Random -Minimum 1 -Maximum 2147483647
    $packet = Build-SnmpGetRequest -Community $Community -Oids $Oids -RequestId $requestId
    $response = Send-SnmpRequest -IP $IP -Packet $packet -TimeoutMs $TimeoutMs
    if (-not $response) { return $null }
    return Parse-SnmpResponse -Data $response
}

function Invoke-SnmpSet {
    param(
        [string]$IP,
        [string]$Oid,
        [byte[]]$ValueTlv,
        [string]$Community = "private",
        [int]$TimeoutMs = 2000
    )
    $requestId = Get-Random -Minimum 1 -Maximum 2147483647
    $packet = Build-SnmpSetRequest -Community $Community -Oid $Oid -ValueTlv $ValueTlv -RequestId $requestId
    $response = Send-SnmpRequest -IP $IP -Packet $packet -TimeoutMs $TimeoutMs
    if (-not $response) { return $null }
    return Parse-SnmpResponse -Data $response
}

function Invoke-SnmpWalk {
    param(
        [string]$IP,
        [string]$RootOid,
        [string]$Community = "public",
        [int]$TimeoutMs = 2000,
        [int]$MaxResults = 100
    )
    $results = @{}
    $currentOid = $RootOid
    $count = 0
    while ($count -lt $MaxResults) {
        $requestId = Get-Random -Minimum 1 -Maximum 2147483647
        $packet = Build-SnmpGetNextRequest -Community $Community -Oids @($currentOid) -RequestId $requestId
        $response = Send-SnmpRequest -IP $IP -Packet $packet -TimeoutMs $TimeoutMs
        if (-not $response) { break }
        $parsed = Parse-SnmpResponse -Data $response
        if (-not $parsed -or $parsed.ErrorStatus -ne 0) { break }
        $nextOid = ($parsed.Results.Keys | Select-Object -First 1)
        if (-not $nextOid -or -not $nextOid.StartsWith($RootOid)) { break }
        $val = $parsed.Results[$nextOid]
        if ($val.Value -eq "endOfMibView") { break }
        $results[$nextOid] = $val
        $currentOid = $nextOid
        $count++
    }
    return $results
}

function Build-PlinkArgs {
    param([string]$Method, [string]$IP, [string]$Username, [string]$Password, [string]$HostKey,
          [int]$Port = 0, [hashtable]$SerialSettings, [switch]$BatchMode)
    switch ($Method) {
        "SSH" {
            $p = if ($Port -gt 0) { $Port } else { 22 }
            $hostKeyArg = ""; if ($HostKey) { $hostKeyArg = "-hostkey `"$HostKey`"" }
            $batchArg = if ($BatchMode) { "-batch" } else { "" }
            if ($Username) { return "-ssh -t -no-antispoof $batchArg $hostKeyArg -l `"$Username`" -pw `"$Password`" -P $p $IP" }
            else { return "-ssh -batch -P $p nobody@$IP" }
        }
        "Telnet" { $p = if ($Port -gt 0) { $Port } else { 23 }; return "-telnet -P $p $IP" }
        "Serial" {
            $comPort = $SerialSettings.ComPort; $speed = $SerialSettings.Speed; $dbits = $SerialSettings.DataBits
            $parityMap = @{ 'None'='n'; 'Odd'='o'; 'Even'='e'; 'Mark'='m'; 'Space'='s' }
            $par = $parityMap[$SerialSettings.Parity]; if (-not $par) { $par = 'n' }
            $sbits = $SerialSettings.StopBits
            $flowMap = @{ 'None'='N'; 'XON/XOFF'='X'; 'RTS/CTS'='R'; 'DSR/DTR'='D' }
            $flow = $flowMap[$SerialSettings.FlowControl]; if (-not $flow) { $flow = 'X' }
            return "-serial $comPort -sercfg $speed,$dbits,$par,$sbits,$flow -no-sanitise-stdout -no-sanitise-stderr"
        }
    }
}

function Get-PlinkHostKey {
    param([string]$PlinkPath, [string]$IP, [int]$Timeout = 10000, [string]$Method = "SSH")
    if ($Method -ne "SSH") { return $null }
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $PlinkPath
    $psi.Arguments = "-ssh -v -batch -P 22 nobody@$IP"
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.RedirectStandardInput = $true
    $psi.CreateNoWindow = $true

    $proc = [System.Diagnostics.Process]::Start($psi)
    $stderr = $proc.StandardError.ReadToEndAsync()
    $stdout = $proc.StandardOutput.ReadToEndAsync()
    if (-not $proc.WaitForExit($Timeout)) {
        try { $proc.Kill() } catch {}
    }
    $errText = $stderr.Result

    foreach ($line in ($errText -split "`n")) {
        if ($line -match '(SHA256:\S+)') {
            return $Matches[1]
        }
    }
    return $null
}

function Invoke-PlinkCommand {
    param([string]$PlinkPath, [string]$IP, [string]$Username, [string]$Password, [string]$HostKey,
          [string[]]$Commands, [int]$Timeout = 15000, [string]$Method = "SSH", [hashtable]$SerialSettings = $null)

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $PlinkPath
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.RedirectStandardInput = $true
    $psi.CreateNoWindow = $true

    if ($Method -eq "Telnet" -or $Method -eq "Serial") {
        # Interactive mode with delays for serial/telnet
        $psi.Arguments = Build-PlinkArgs -Method $Method -IP $IP -Username $Username `
            -Password $Password -HostKey $HostKey -SerialSettings $SerialSettings
        $proc = [System.Diagnostics.Process]::Start($psi)

        # Start async reads immediately before any stdin writes
        $stdoutTask = $proc.StandardOutput.ReadToEndAsync()
        $stderrTask = $proc.StandardError.ReadToEndAsync()

        Start-Sleep -Milliseconds 1000
        if ($Method -eq "Telnet") {
            $proc.StandardInput.WriteLine($Username)
            $proc.StandardInput.Flush()
            Start-Sleep -Milliseconds 500
            $proc.StandardInput.WriteLine($Password)
            $proc.StandardInput.Flush()
            Start-Sleep -Milliseconds 1000
        }
        foreach ($cmd in $Commands) {
            $proc.StandardInput.WriteLine($cmd)
            $proc.StandardInput.Flush()
            Start-Sleep -Milliseconds 500
        }
        Start-Sleep -Milliseconds 1000
        $proc.StandardInput.Close()

        $effectiveTimeout = [Math]::Max($Timeout, 20000)
        if (-not $proc.WaitForExit($effectiveTimeout)) {
            try { $proc.Kill() } catch {}
        }
        $stdout = ""; $stderr = ""
        try { if ($stdoutTask.Wait(5000)) { $stdout = $stdoutTask.Result } } catch {}
        try { if ($stderrTask.Wait(5000)) { $stderr = $stderrTask.Result } } catch {}
        $exitCode = $proc.ExitCode
        try { $proc.Dispose() } catch {}
        return @{ StdOut = $stdout; StdErr = $stderr; ExitCode = $exitCode }
    } else {
        # SSH batch mode
        $Commands = @($Commands)
        $commandText = ($Commands -join "`n") + "`n"
        $psi.Arguments = Build-PlinkArgs -Method $Method -IP $IP -Username $Username `
            -Password $Password -HostKey $HostKey -SerialSettings $SerialSettings -BatchMode
        $proc = [System.Diagnostics.Process]::Start($psi)
        $proc.StandardInput.Write($commandText)
        $proc.StandardInput.Flush()
        $proc.StandardInput.Close()

        $stdoutTask = $proc.StandardOutput.ReadToEndAsync()
        $stderrTask = $proc.StandardError.ReadToEndAsync()
        if (-not $proc.WaitForExit($Timeout)) {
            try { $proc.Kill() } catch {}
        }
        $exitCode = $proc.ExitCode
        try { $proc.Dispose() } catch {}
        return @{ StdOut = $stdoutTask.Result; StdErr = $stderrTask.Result; ExitCode = $exitCode }
    }
}

function Invoke-PlinkInteractive {
    param([string]$PlinkPath, [string]$IP, [string]$Username, [string]$Password, [string]$HostKey,
          [string[]]$Commands, [int]$Timeout = 60000, [int]$ReadDelay = 8000,
          [string]$Method = "SSH", [hashtable]$SerialSettings = $null)

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $PlinkPath
    $psi.Arguments = Build-PlinkArgs -Method $Method -IP $IP -Username $Username `
        -Password $Password -HostKey $HostKey -SerialSettings $SerialSettings
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.RedirectStandardInput = $true
    $psi.CreateNoWindow = $true

    $proc = [System.Diagnostics.Process]::Start($psi)

    # Start async reads IMMEDIATELY after process start, before any stdin writes.
    # This ensures output is being buffered from the very beginning.
    $stdoutTask = $proc.StandardOutput.ReadToEndAsync()
    $stderrTask = $proc.StandardError.ReadToEndAsync()

    if ($Method -eq "Serial" -or $Method -eq "Telnet") {
        # Send a blank line to wake the console and wait for prompt
        Start-Sleep -Milliseconds 2000
        $proc.StandardInput.WriteLine("")
        $proc.StandardInput.Flush()
        Start-Sleep -Milliseconds 1000

        if ($Method -eq "Telnet") {
            # Telnet requires login credentials
            $proc.StandardInput.WriteLine($Username)
            $proc.StandardInput.Flush()
            Start-Sleep -Milliseconds 800
            $proc.StandardInput.WriteLine($Password)
            $proc.StandardInput.Flush()
            Start-Sleep -Milliseconds 1500
        }
        # Serial console: skip credentials — console is already at the prompt.

        # Send each command with appropriate delays
        foreach ($cmd in $Commands) {
            $proc.StandardInput.WriteLine($cmd)
            $proc.StandardInput.Flush()
            # Longer delay for commands that produce large output over slow serial
            if ($cmd -match 'show running-config' -or $cmd -match 'show startup-config' -or $cmd -match 'show tech') {
                $cmdWait = if ($Method -eq "Serial") { 30000 } else { 10000 }
                Start-Sleep -Milliseconds $cmdWait
            } else {
                Start-Sleep -Milliseconds 1000
            }
        }

        # Extra wait for serial to flush remaining buffered output
        $finalWait = if ($Method -eq "Serial") { 5000 } else { $ReadDelay }
        Start-Sleep -Milliseconds $finalWait
    } else {
        # SSH: send all commands with minimal delays (SSH buffers reliably)
        foreach ($cmd in $Commands) {
            Start-Sleep -Milliseconds 200
            $proc.StandardInput.WriteLine($cmd)
            $proc.StandardInput.Flush()
        }
        Start-Sleep -Milliseconds $ReadDelay
    }

    $proc.StandardInput.Close()

    # Use a longer timeout for serial connections
    $effectiveTimeout = if ($Method -eq "Serial") { [Math]::Max($Timeout, 120000) } else { $Timeout }
    if (-not $proc.WaitForExit($effectiveTimeout)) {
        try { $proc.Kill() } catch {}
    }

    # Wait for async reads to complete (they finish when process closes pipes)
    $stdout = ""; $stderr = ""
    try { if ($stdoutTask.Wait(5000)) { $stdout = $stdoutTask.Result } } catch {}
    try { if ($stderrTask.Wait(5000)) { $stderr = $stderrTask.Result } } catch {}

    $exitCode = $proc.ExitCode
    # Dispose process to release COM port handle immediately
    try { $proc.Dispose() } catch {}

    return @{ StdOut = $stdout; StdErr = $stderr; ExitCode = $exitCode }
}

function Get-SwitchIdentity {
    param(
        [string]$PlinkPath,
        [string]$IP,
        [string]$HostKey,
        [array]$Credentials
    )
    $result = @{
        Type       = "Unknown"
        Hostname   = ""
        Model      = ""
        Username   = ""
        Password   = ""
        EnablePass = ""
        Error      = ""
        Banner     = ""
    }

    foreach ($cred in $Credentials) {
        $user = $cred.Username
        $pass = $cred.Password
        $enable = $cred.EnablePassword

        # Try batch mode first to get banner and identify
        $resp = Invoke-PlinkCommand -PlinkPath $PlinkPath -IP $IP -Username $user -Password $pass `
            -HostKey $HostKey -Commands @("exit") -Timeout 15000

        $combined = "$($resp.StdOut)`n$($resp.StdErr)"
        $result.Banner = $combined

        # Check for auth failure
        if ($combined -match 'Access denied' -or $combined -match 'FATAL ERROR' -or
            $combined -match 'Unable to authenticate' -or $combined -match 'password:') {
            continue
        }

        # Hirschmann detection
        if ($combined -match 'Hirschmann' -or $combined -match 'HiOS' -or $combined -match 'HiLCOS') {
            $result.Type = "Hirschmann"
            $result.Username = $user
            $result.Password = $pass
            $result.EnablePass = $enable

            # Extract model from banner
            if ($combined -match '(MSP\S+|RSP\S+|BRS\S+|OCTOPUS\S+|MACH\S+|RSPS?\S+|OS\S+)\s+Release\s+(\S+)') {
                $result.Model = "$($Matches[1]) $($Matches[2])"
            } elseif ($combined -match '(\S+)\s+Release\s+(HiOS\S+)') {
                $result.Model = "$($Matches[1]) $($Matches[2])"
            }

            # Extract hostname - look for System Name in banner
            if ($combined -match 'System Name\s*:\s*(.+)') {
                $result.Hostname = $Matches[1].Trim()
            } elseif ($combined -match 'NOTE:\s+(.+)') {
                $result.Hostname = $Matches[1].Trim()
            }
            return $result
        }

        # Cisco detection from banner
        if ($combined -match 'Cisco' -or $combined -match 'IOS') {
            $result.Type = "Cisco"
            $result.Username = $user
            $result.Password = $pass
            $result.EnablePass = $enable

            if ($combined -match '(\S+)[#>]\s*$') {
                $result.Hostname = $Matches[1].Trim()
            }
            # Probe with 'show version' for model info
            $probeCmds = @("terminal length 0", "show version", "exit")
            if ($enable) {
                $probeCmds = @("enable", $enable, "terminal length 0", "show version", "exit")
            }
            $probeResp = Invoke-PlinkInteractive -PlinkPath $PlinkPath -IP $IP -Username $user -Password $pass `
                -HostKey $HostKey -Commands $probeCmds -Timeout 20000 -ReadDelay 4000
            $probeOut = "$($probeResp.StdOut)`n$($probeResp.StdErr)"
            if ($probeOut -match 'Model\s+[Nn]umber\s*:\s*(\S+)') {
                $result.Model = $Matches[1].Trim()
            } elseif ($probeOut -match 'cisco\s+(IE-\S+|IE\S+|C\S+|WS-\S+|N\S+)\s') {
                $result.Model = $Matches[1].Trim()
            } elseif ($probeOut -match '(\S+)\s+processor.*with\s+\d+') {
                $result.Model = $Matches[1].Trim()
            }
            if ($probeOut -match 'Version\s+(\d+\.\d+\S*)') {
                $result.Model = "$($result.Model) IOS $($Matches[1].Trim())".Trim()
            }
            return $result
        }

        # If authenticated but not identified, probe with 'show version'
        if ($resp.ExitCode -eq 0 -and $combined.Length -gt 0) {
            $result.Username = $user
            $result.Password = $pass
            $result.EnablePass = $enable

            $probeCmds = @("terminal length 0", "show version", "exit")
            if ($enable) {
                $probeCmds = @("enable", $enable, "terminal length 0", "show version", "exit")
            }
            $probeResp = Invoke-PlinkInteractive -PlinkPath $PlinkPath -IP $IP -Username $user -Password $pass `
                -HostKey $HostKey -Commands $probeCmds -Timeout 20000 -ReadDelay 4000
            $probeOut = "$($probeResp.StdOut)`n$($probeResp.StdErr)"

            if ($probeOut -match 'Cisco' -or $probeOut -match 'IOS') {
                $result.Type = "Cisco"
                if ($probeOut -match '(\S+)[#>]\s') {
                    $result.Hostname = $Matches[1].Trim()
                }
                if ($probeOut -match 'Model\s+[Nn]umber\s*:\s*(\S+)') {
                    $result.Model = $Matches[1].Trim()
                } elseif ($probeOut -match 'cisco\s+(IE-\S+|IE\S+|C\S+|WS-\S+|N\S+)\s') {
                    $result.Model = $Matches[1].Trim()
                } elseif ($probeOut -match '(\S+)\s+processor.*with\s+\d+') {
                    $result.Model = $Matches[1].Trim()
                }
                if ($probeOut -match 'Version\s+(\d+\.\d+\S*)') {
                    $result.Model = "$($result.Model) IOS $($Matches[1].Trim())".Trim()
                }
            } else {
                $result.Type = "Unknown"
                $result.Hostname = "Authenticated"
            }
            return $result
        }
    }

    $result.Error = "Auth failed for all credentials"
    return $result
}

function Get-HirschmannConfig {
    param(
        [string]$PlinkPath,
        [string]$IP,
        [string]$Username,
        [string]$Password,
        [string]$HostKey
    )
    # Send show running-config script followed by spaces for pagination
    $spaces = " " * 200
    $commands = @("show running-config script", $spaces, $spaces, $spaces, $spaces, $spaces, "exit")

    $resp = Invoke-PlinkInteractive -PlinkPath $PlinkPath -IP $IP -Username $Username -Password $Password `
        -HostKey $HostKey -Commands $commands -Timeout 60000 -ReadDelay 8000

    return @{
        StdOut   = $resp.StdOut
        StdErr   = $resp.StdErr
        ExitCode = $resp.ExitCode
    }
}

function Get-CiscoConfig {
    param(
        [string]$PlinkPath,
        [string]$IP,
        [string]$Username,
        [string]$Password,
        [string]$EnablePassword,
        [string]$HostKey
    )
    $commands = @(
        "enable",
        $EnablePassword,
        "terminal length 0",
        "show running-config",
        "exit"
    )

    $resp = Invoke-PlinkInteractive -PlinkPath $PlinkPath -IP $IP -Username $Username -Password $Password `
        -HostKey $HostKey -Commands $commands -Timeout 60000 -ReadDelay 8000

    return @{
        StdOut   = $resp.StdOut
        StdErr   = $resp.StdErr
        ExitCode = $resp.ExitCode
    }
}

function Clean-HirschmannOutput {
    param([string]$RawOutput)
    $lines = $RawOutput -split "`n"
    $cleaned = @()
    $inConfig = $false

    foreach ($line in $lines) {
        $trimmed = $line.TrimEnd("`r")

        # Detect start of config block
        if (-not $inConfig) {
            if ($trimmed -match '^!\s+\S+.*Configuration' -or $trimmed -match '^! (MSP|BRS|RSP|OCTOPUS|MACH)') {
                $inConfig = $true
                $cleaned += $trimmed
                continue
            }
            # Also start if we see the first config command
            if ($trimmed -match '^interface \d' -or $trimmed -match '^vlan' -or $trimmed -match '^spanning-tree') {
                $inConfig = $true
                $cleaned += $trimmed
                continue
            }
            continue
        }

        # Stop at prompt
        if ($trimmed -match '^\(MSP\)' -or $trimmed -match '^\(BRS\)' -or $trimmed -match '^\(RSP\)' -or
            $trimmed -match '^\(OCTOPUS\)' -or $trimmed -match '^\(MACH\)' -or $trimmed -match '^\S+[>#]\s*$') {
            break
        }

        # Skip --More-- lines and artifacts
        if ($trimmed -match '--More--' -or $trimmed -match '^\s*$' -and $trimmed.Length -gt 80) {
            continue
        }

        # Remove any --More-- inline markers
        $trimmed = $trimmed -replace '\x1b\[[0-9;]*[a-zA-Z]', ''  # Remove ANSI escapes
        $trimmed = $trimmed -replace '--More--', ''
        $trimmed = $trimmed -replace '\x08+\s+\x08+', ''  # Remove backspace sequences

        $cleaned += $trimmed
    }

    # If we didn't find the config start marker, try a more lenient approach
    if ($cleaned.Count -eq 0) {
        $inConfig = $false
        foreach ($line in $lines) {
            $trimmed = $line.TrimEnd("`r")
            $trimmed = $trimmed -replace '\x1b\[[0-9;]*[a-zA-Z]', ''
            $trimmed = $trimmed -replace '--More--', ''
            $trimmed = $trimmed -replace '\x08+\s+\x08+', ''

            if ($trimmed -match '^!') {
                $inConfig = $true
            }
            if ($inConfig) {
                if ($trimmed -match '^\(MSP\)' -or $trimmed -match '^\(BRS\)' -or $trimmed -match '^\(RSP\)') {
                    break
                }
                $cleaned += $trimmed
            }
        }
    }

    return ($cleaned -join "`n").Trim()
}

function Clean-CiscoOutput {
    param([string]$RawOutput)
    $lines = $RawOutput -split "`n"
    $cleaned = @()
    $inConfig = $false

    foreach ($line in $lines) {
        $trimmed = $line.TrimEnd("`r")

        if (-not $inConfig) {
            if ($trimmed -match 'Building configuration' -or $trimmed -match 'Current configuration') {
                $inConfig = $true
                $cleaned += $trimmed
                continue
            }
            continue
        }

        $cleaned += $trimmed

        if ($trimmed -match '^end\s*$') {
            break
        }
    }

    return ($cleaned -join "`n").Trim()
}

function Clean-AnsiOutput {
    param([string]$RawOutput)
    $cleaned = $RawOutput -replace '\x1b\[[0-9;]*[a-zA-Z]', ''
    $cleaned = $cleaned -replace '\x08+\s+\x08+', ''
    $cleaned = $cleaned -replace '--More--\s*', ''
    return $cleaned
}

function Add-SyncLog {
    param([hashtable]$SyncHash, [string]$Channel, [string]$Message)
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$ts] $Message"
    switch ($Channel) {
        "Backup"    { $SyncHash.BackupLog += $entry }
        "Audit"     { $SyncHash.AuditLog += $entry }
        "Discovery" { $SyncHash.DiscoveryLog += $entry }
    }
}

function PrefixToMask {
    param([int]$Prefix)
    if ($Prefix -lt 0 -or $Prefix -gt 32) { return "255.255.255.0" }
    $mask = ([uint32]([Math]::Pow(2, 32) - 1)) -shl (32 - $Prefix)
    $b1 = ($mask -shr 24) -band 0xFF
    $b2 = ($mask -shr 16) -band 0xFF
    $b3 = ($mask -shr 8) -band 0xFF
    $b4 = $mask -band 0xFF
    return "$b1.$b2.$b3.$b4"
}

function Export-EncryptedCredentials {
    param(
        [array]$Credentials,
        [string]$FilePath
    )
    $exportList = @()
    foreach ($cred in $Credentials) {
        $secPass = ConvertTo-SecureString $cred.Password -AsPlainText -Force
        $secEnable = ConvertTo-SecureString $cred.EnablePassword -AsPlainText -Force
        $exportList += @{
            Username       = $cred.Username
            Password       = ($secPass | ConvertFrom-SecureString)
            EnablePassword = ($secEnable | ConvertFrom-SecureString)
        }
    }
    $exportList | Export-Clixml -Path $FilePath -Force
}

function Import-EncryptedCredentials {
    param([string]$FilePath)
    if (-not (Test-Path $FilePath)) { return @() }

    $importList = Import-Clixml -Path $FilePath
    $creds = @()
    foreach ($item in $importList) {
        try {
            $secPass = ConvertTo-SecureString $item.Password
            $secEnable = ConvertTo-SecureString $item.EnablePassword
            $passPtr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secPass)
            $enablePtr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secEnable)
            $creds += @{
                Username       = $item.Username
                Password       = [Runtime.InteropServices.Marshal]::PtrToStringAuto($passPtr)
                EnablePassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto($enablePtr)
            }
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passPtr)
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($enablePtr)
        } catch {
            # Skip entries that can't be decrypted (different user/machine)
        }
    }
    return $creds
}

function Save-CommandList {
    param(
        [string[]]$Commands,
        [string]$FilePath
    )
    try {
        $Commands | ConvertTo-Json | Set-Content -Path $FilePath -Encoding UTF8 -Force
    } catch {}
}

function Load-CommandList {
    param([string]$FilePath)
    if (-not (Test-Path $FilePath)) { return $null }
    try {
        $json = Get-Content -Path $FilePath -Raw -Encoding UTF8
        $list = $json | ConvertFrom-Json
        if ($list -and $list.Count -gt 0) { return @($list) }
    } catch {}
    return $null
}

# ---------------------------------------------------------------------------
# Build the GUI
# ---------------------------------------------------------------------------

$plinkPath = Find-Plink

# Synchronized hashtable for cross-thread communication
$sync = [hashtable]::Synchronized(@{
    Cancel          = $false
    ScanResults     = @()
    ScanProgress    = 0
    ScanTotal       = 0
    ScanStatus      = ""
    ScanComplete    = $false
    IdentifyResults = @()
    IdentifyStatus  = ""
    IdentifyComplete = $false
    BackupResults   = @()
    BackupStatus    = ""
    BackupComplete  = $false
    BackupLog       = @()
    LogIndex        = 0
    WatchdogCancel   = $false
    WatchdogResults  = @{}
    WatchdogUpdated  = $false
    AuditResults     = @()
    AuditStatus      = ""
    AuditComplete    = $false
    AuditLog         = @()
    AuditLogIndex    = 0
    DiscoveryResults   = @()
    DiscoveryProgress  = 0
    DiscoveryTotal     = 0
    DiscoveryStatus    = ""
    DiscoveryComplete  = $false
    DiscoveryLog       = @()
    DiscoveryLogIndex  = 0
    DiscoveryCancel    = $false
})

# Store discovered devices
$script:devices = [System.Collections.ArrayList]::new()
$script:credentials = [System.Collections.ArrayList]::new()
$script:runspacePool = $null
$script:activeRunspace = $null
$script:watchdogRunspace = $null
$script:discoveryRunspace = $null
$script:watchdogRunning = $false
$script:showPasswords = $false
$script:credFilePath = Join-Path $PSScriptRoot "switch_creds.xml"
$script:ciscoCmdsFilePath = Join-Path $PSScriptRoot "audit_cisco_commands.json"
$script:hirschmannCmdsFilePath = Join-Path $PSScriptRoot "audit_hirschmann_commands.json"
$script:connectionMethod = "SSH"
$script:vendorOverride = "Auto-Detect"

# ---------------------------------------------------------------------------
# Shared InitialSessionState — inject helper functions into all runspaces
# ---------------------------------------------------------------------------
$script:sharedISS = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
$sharedFunctionNames = @(
    'Build-PlinkArgs', 'Get-PlinkHostKey', 'Invoke-PlinkCommand',
    'Invoke-PlinkInteractive', 'Sanitize-Filename',
    'Clean-HirschmannOutput', 'Clean-CiscoOutput', 'Clean-AnsiOutput',
    'Add-SyncLog', 'PrefixToMask'
)
foreach ($funcName in $sharedFunctionNames) {
    $funcBody = (Get-Command -Name $funcName -CommandType Function).ScriptBlock.ToString()
    $null = $script:sharedISS.Commands.Add(
        [System.Management.Automation.Runspaces.SessionStateFunctionEntry]::new($funcName, $funcBody)
    )
}

# ---------------------------------------------------------------------------
# Theme Definitions
# ---------------------------------------------------------------------------
$script:themes = @{
    'Light' = @{
        FormBack    = [System.Drawing.SystemColors]::Control
        FormFore    = [System.Drawing.SystemColors]::ControlText
        ControlBack = [System.Drawing.Color]::White
        ControlFore = [System.Drawing.Color]::Black
        GridBack    = [System.Drawing.Color]::White
        GridFore    = [System.Drawing.Color]::Black
        GridAltBack = [System.Drawing.Color]::FromArgb(245, 245, 245)
        ButtonBack  = [System.Drawing.SystemColors]::Control
        ButtonFore  = [System.Drawing.SystemColors]::ControlText
        AccentColor = [System.Drawing.Color]::FromArgb(0, 120, 215)
        LogBack     = [System.Drawing.Color]::FromArgb(30, 30, 30)
        LogFore     = [System.Drawing.Color]::LightGreen
        ButtonFlat  = $false
    }
    'Dark' = @{
        FormBack    = [System.Drawing.Color]::FromArgb(45, 45, 48)
        FormFore    = [System.Drawing.Color]::FromArgb(241, 241, 241)
        ControlBack = [System.Drawing.Color]::FromArgb(51, 51, 55)
        ControlFore = [System.Drawing.Color]::FromArgb(241, 241, 241)
        GridBack    = [System.Drawing.Color]::FromArgb(37, 37, 38)
        GridFore    = [System.Drawing.Color]::FromArgb(241, 241, 241)
        GridAltBack = [System.Drawing.Color]::FromArgb(45, 45, 48)
        ButtonBack  = [System.Drawing.Color]::FromArgb(62, 62, 66)
        ButtonFore  = [System.Drawing.Color]::FromArgb(241, 241, 241)
        AccentColor = [System.Drawing.Color]::FromArgb(0, 122, 204)
        LogBack     = [System.Drawing.Color]::FromArgb(30, 30, 30)
        LogFore     = [System.Drawing.Color]::LightGreen
        ButtonFlat  = $true
    }
    'Nord' = @{
        FormBack    = [System.Drawing.Color]::FromArgb(46, 52, 64)
        FormFore    = [System.Drawing.Color]::FromArgb(236, 239, 244)
        ControlBack = [System.Drawing.Color]::FromArgb(59, 66, 82)
        ControlFore = [System.Drawing.Color]::FromArgb(236, 239, 244)
        GridBack    = [System.Drawing.Color]::FromArgb(46, 52, 64)
        GridFore    = [System.Drawing.Color]::FromArgb(229, 233, 240)
        GridAltBack = [System.Drawing.Color]::FromArgb(59, 66, 82)
        ButtonBack  = [System.Drawing.Color]::FromArgb(67, 76, 94)
        ButtonFore  = [System.Drawing.Color]::FromArgb(236, 239, 244)
        AccentColor = [System.Drawing.Color]::FromArgb(136, 192, 208)
        LogBack     = [System.Drawing.Color]::FromArgb(46, 52, 64)
        LogFore     = [System.Drawing.Color]::FromArgb(163, 190, 140)
        ButtonFlat  = $true
    }
    'Solarized' = @{
        FormBack    = [System.Drawing.Color]::FromArgb(0, 43, 54)
        FormFore    = [System.Drawing.Color]::FromArgb(131, 148, 150)
        ControlBack = [System.Drawing.Color]::FromArgb(7, 54, 66)
        ControlFore = [System.Drawing.Color]::FromArgb(131, 148, 150)
        GridBack    = [System.Drawing.Color]::FromArgb(0, 43, 54)
        GridFore    = [System.Drawing.Color]::FromArgb(131, 148, 150)
        GridAltBack = [System.Drawing.Color]::FromArgb(7, 54, 66)
        ButtonBack  = [System.Drawing.Color]::FromArgb(7, 54, 66)
        ButtonFore  = [System.Drawing.Color]::FromArgb(147, 161, 161)
        AccentColor = [System.Drawing.Color]::FromArgb(38, 139, 210)
        LogBack     = [System.Drawing.Color]::FromArgb(0, 43, 54)
        LogFore     = [System.Drawing.Color]::FromArgb(133, 153, 0)
        ButtonFlat  = $true
    }
    'Monokai' = @{
        FormBack    = [System.Drawing.Color]::FromArgb(39, 40, 34)
        FormFore    = [System.Drawing.Color]::FromArgb(248, 248, 242)
        ControlBack = [System.Drawing.Color]::FromArgb(49, 50, 44)
        ControlFore = [System.Drawing.Color]::FromArgb(248, 248, 242)
        GridBack    = [System.Drawing.Color]::FromArgb(39, 40, 34)
        GridFore    = [System.Drawing.Color]::FromArgb(248, 248, 242)
        GridAltBack = [System.Drawing.Color]::FromArgb(49, 50, 44)
        ButtonBack  = [System.Drawing.Color]::FromArgb(59, 60, 54)
        ButtonFore  = [System.Drawing.Color]::FromArgb(248, 248, 242)
        AccentColor = [System.Drawing.Color]::FromArgb(166, 226, 46)
        LogBack     = [System.Drawing.Color]::FromArgb(39, 40, 34)
        LogFore     = [System.Drawing.Color]::FromArgb(166, 226, 46)
        ButtonFlat  = $true
    }
    'Ocean Blue' = @{
        FormBack    = [System.Drawing.Color]::FromArgb(27, 40, 56)
        FormFore    = [System.Drawing.Color]::FromArgb(199, 213, 224)
        ControlBack = [System.Drawing.Color]::FromArgb(35, 51, 71)
        ControlFore = [System.Drawing.Color]::FromArgb(199, 213, 224)
        GridBack    = [System.Drawing.Color]::FromArgb(27, 40, 56)
        GridFore    = [System.Drawing.Color]::FromArgb(199, 213, 224)
        GridAltBack = [System.Drawing.Color]::FromArgb(35, 51, 71)
        ButtonBack  = [System.Drawing.Color]::FromArgb(42, 62, 88)
        ButtonFore  = [System.Drawing.Color]::FromArgb(199, 213, 224)
        AccentColor = [System.Drawing.Color]::FromArgb(102, 192, 244)
        LogBack     = [System.Drawing.Color]::FromArgb(27, 40, 56)
        LogFore     = [System.Drawing.Color]::FromArgb(102, 192, 244)
        ButtonFlat  = $true
    }
    'High Contrast' = @{
        FormBack    = [System.Drawing.Color]::Black
        FormFore    = [System.Drawing.Color]::White
        ControlBack = [System.Drawing.Color]::FromArgb(20, 20, 20)
        ControlFore = [System.Drawing.Color]::White
        GridBack    = [System.Drawing.Color]::Black
        GridFore    = [System.Drawing.Color]::White
        GridAltBack = [System.Drawing.Color]::FromArgb(30, 30, 30)
        ButtonBack  = [System.Drawing.Color]::FromArgb(40, 40, 40)
        ButtonFore  = [System.Drawing.Color]::Yellow
        AccentColor = [System.Drawing.Color]::Yellow
        LogBack     = [System.Drawing.Color]::Black
        LogFore     = [System.Drawing.Color]::FromArgb(0, 255, 0)
        ButtonFlat  = $true
    }
}

function Apply-Theme {
    param([string]$ThemeName)
    $t = $script:themes[$ThemeName]
    if (-not $t) { return }

    $form.BackColor = $t.FormBack
    $form.ForeColor = $t.FormFore

    function Apply-ToControl {
        param($Control, $Theme)
        if ($Control -is [System.Windows.Forms.DataGridView]) {
            $Control.BackgroundColor = $Theme.GridBack
            $Control.DefaultCellStyle.BackColor = $Theme.GridBack
            $Control.DefaultCellStyle.ForeColor = $Theme.GridFore
            $Control.DefaultCellStyle.SelectionBackColor = $Theme.AccentColor
            $Control.DefaultCellStyle.SelectionForeColor = [System.Drawing.Color]::White
            $Control.AlternatingRowsDefaultCellStyle.BackColor = $Theme.GridAltBack
            $Control.AlternatingRowsDefaultCellStyle.ForeColor = $Theme.GridFore
            $Control.ColumnHeadersDefaultCellStyle.BackColor = $Theme.ButtonBack
            $Control.ColumnHeadersDefaultCellStyle.ForeColor = $Theme.ButtonFore
            $Control.EnableHeadersVisualStyles = $false
            $Control.GridColor = $Theme.AccentColor
        }
        elseif ($Control -is [System.Windows.Forms.RichTextBox]) {
            $Control.BackColor = $Theme.LogBack
            $Control.ForeColor = $Theme.LogFore
        }
        elseif ($Control -is [System.Windows.Forms.Button]) {
            $Control.BackColor = $Theme.ButtonBack
            $Control.ForeColor = $Theme.ButtonFore
            if ($Theme.ButtonFlat) {
                $Control.FlatStyle = 'Flat'
                $Control.FlatAppearance.BorderColor = $Theme.AccentColor
            } else {
                $Control.FlatStyle = 'Standard'
                $Control.UseVisualStyleBackColor = $true
            }
        }
        elseif ($Control -is [System.Windows.Forms.TextBox]) {
            $Control.BackColor = $Theme.ControlBack
            $Control.ForeColor = $Theme.ControlFore
        }
        elseif ($Control -is [System.Windows.Forms.ComboBox]) {
            $Control.BackColor = $Theme.ControlBack
            $Control.ForeColor = $Theme.ControlFore
        }
        elseif ($Control -is [System.Windows.Forms.CheckBox]) {
            $Control.BackColor = $Theme.FormBack
            $Control.ForeColor = $Theme.FormFore
        }
        elseif ($Control -is [System.Windows.Forms.ProgressBar]) {
            $Control.BackColor = $Theme.ControlBack
        }
        elseif ($Control -is [System.Windows.Forms.TabControl]) {
            $Control.BackColor = $Theme.FormBack
            $Control.ForeColor = $Theme.FormFore
        }
        elseif ($Control -is [System.Windows.Forms.TabPage]) {
            $Control.BackColor = $Theme.FormBack
            $Control.ForeColor = $Theme.FormFore
        }
        elseif ($Control -is [System.Windows.Forms.Panel]) {
            $Control.BackColor = $Theme.FormBack
            $Control.ForeColor = $Theme.FormFore
        }
        elseif ($Control -is [System.Windows.Forms.SplitContainer]) {
            $Control.BackColor = $Theme.FormBack
            $Control.ForeColor = $Theme.FormFore
        }
        elseif ($Control -is [System.Windows.Forms.Label]) {
            $Control.BackColor = $Theme.FormBack
            $Control.ForeColor = $Theme.FormFore
        }
        elseif ($Control -is [System.Windows.Forms.GroupBox]) {
            $Control.BackColor = $Theme.FormBack
            $Control.ForeColor = $Theme.FormFore
        }
        elseif ($Control -is [System.Windows.Forms.NumericUpDown]) {
            $Control.BackColor = $Theme.ControlBack
            $Control.ForeColor = $Theme.ControlFore
        }

        if ($Control.HasChildren) {
            foreach ($child in $Control.Controls) {
                Apply-ToControl -Control $child -Theme $Theme
            }
        }
    }

    foreach ($ctrl in $form.Controls) {
        Apply-ToControl -Control $ctrl -Theme $t
    }
}

# ---------------------------------------------------------------------------
# Main Form
# ---------------------------------------------------------------------------
$form = New-Object System.Windows.Forms.Form
$form.Text = "Switch Config Backup Tool"
$form.Size = New-Object System.Drawing.Size(950, 720)
$form.StartPosition = "CenterScreen"
$form.MinimumSize = New-Object System.Drawing.Size(900, 650)
$form.Font = New-Object System.Drawing.Font("Segoe UI", 9)

# Theme selection panel at top of form
$panelTheme = New-Object System.Windows.Forms.Panel
$panelTheme.Dock = 'Top'
$panelTheme.Height = 32
$form.Controls.Add($panelTheme)

$lblTheme = New-Object System.Windows.Forms.Label
$lblTheme.Text = "Theme:"
$lblTheme.Location = New-Object System.Drawing.Point(8, 7)
$lblTheme.AutoSize = $true
$panelTheme.Controls.Add($lblTheme)

$cboTheme = New-Object System.Windows.Forms.ComboBox
$cboTheme.DropDownStyle = 'DropDownList'
$cboTheme.Location = New-Object System.Drawing.Point(60, 4)
$cboTheme.Size = New-Object System.Drawing.Size(140, 23)
$cboTheme.Items.AddRange(@('Light', 'Dark', 'Nord', 'Solarized', 'Monokai', 'Ocean Blue', 'High Contrast'))
$cboTheme.SelectedIndex = 0
$panelTheme.Controls.Add($cboTheme)

$tabControl = New-Object System.Windows.Forms.TabControl
$tabControl.Dock = 'Fill'
$form.Controls.Add($tabControl)

# Ensure correct Z-order: panelTheme (Top) must have higher index so it docks first,
# then tabControl (Fill) fills the remaining space below it.
$form.Controls.SetChildIndex($panelTheme, 0)
$form.Controls.SetChildIndex($tabControl, 0)

# ---------------------------------------------------------------------------
# Tab 1: Scan & Discover
# ---------------------------------------------------------------------------
$tabScan = New-Object System.Windows.Forms.TabPage
$tabScan.Text = "Scan && Discover"
$tabScan.Padding = New-Object System.Windows.Forms.Padding(8)
$tabControl.TabPages.Add($tabScan)

$panelScanTop = New-Object System.Windows.Forms.Panel
$panelScanTop.Dock = 'Top'
$panelScanTop.Height = 165
$tabScan.Controls.Add($panelScanTop)

$lblSubnet = New-Object System.Windows.Forms.Label
$lblSubnet.Text = "Subnet (CIDR):"
$lblSubnet.Location = New-Object System.Drawing.Point(5, 12)
$lblSubnet.AutoSize = $true
$panelScanTop.Controls.Add($lblSubnet)

$txtSubnet = New-Object System.Windows.Forms.TextBox
$txtSubnet.Location = New-Object System.Drawing.Point(110, 9)
$txtSubnet.Size = New-Object System.Drawing.Size(200, 23)
$txtSubnet.Text = "192.168.105.0/24"
$panelScanTop.Controls.Add($txtSubnet)

$btnScan = New-Object System.Windows.Forms.Button
$btnScan.Text = "Scan"
$btnScan.Location = New-Object System.Drawing.Point(320, 7)
$btnScan.Size = New-Object System.Drawing.Size(80, 27)
$panelScanTop.Controls.Add($btnScan)

$btnScanStop = New-Object System.Windows.Forms.Button
$btnScanStop.Text = "Stop"
$btnScanStop.Location = New-Object System.Drawing.Point(405, 7)
$btnScanStop.Size = New-Object System.Drawing.Size(80, 27)
$btnScanStop.Enabled = $false
$panelScanTop.Controls.Add($btnScanStop)

$lblPlinkStatus = New-Object System.Windows.Forms.Label
$lblPlinkStatus.Location = New-Object System.Drawing.Point(500, 12)
$lblPlinkStatus.AutoSize = $true
if ($plinkPath) {
    $lblPlinkStatus.Text = "plink: $plinkPath"
    $lblPlinkStatus.ForeColor = [System.Drawing.Color]::Green
} else {
    $lblPlinkStatus.Text = "plink.exe not found! Connection features disabled."
    $lblPlinkStatus.ForeColor = [System.Drawing.Color]::Red
}
$panelScanTop.Controls.Add($lblPlinkStatus)

$progressScan = New-Object System.Windows.Forms.ProgressBar
$progressScan.Location = New-Object System.Drawing.Point(5, 42)
$progressScan.Size = New-Object System.Drawing.Size(900, 20)
$progressScan.Anchor = 'Top,Left,Right'
$panelScanTop.Controls.Add($progressScan)

$lblScanStatus = New-Object System.Windows.Forms.Label
$lblScanStatus.Location = New-Object System.Drawing.Point(5, 67)
$lblScanStatus.Size = New-Object System.Drawing.Size(900, 18)
$lblScanStatus.Anchor = 'Top,Left,Right'
$lblScanStatus.Text = "Ready"
$panelScanTop.Controls.Add($lblScanStatus)

$lblConnMethod = New-Object System.Windows.Forms.Label
$lblConnMethod.Text = "Connection:"
$lblConnMethod.Location = New-Object System.Drawing.Point(5, 95)
$lblConnMethod.AutoSize = $true
$panelScanTop.Controls.Add($lblConnMethod)

$cboConnMethod = New-Object System.Windows.Forms.ComboBox
$cboConnMethod.DropDownStyle = 'DropDownList'
$cboConnMethod.Location = New-Object System.Drawing.Point(85, 92)
$cboConnMethod.Size = New-Object System.Drawing.Size(100, 23)
$cboConnMethod.Items.AddRange(@('SSH', 'Telnet'))
$cboConnMethod.SelectedIndex = 0
$panelScanTop.Controls.Add($cboConnMethod)

$lblVendor = New-Object System.Windows.Forms.Label
$lblVendor.Text = "Vendor:"
$lblVendor.Location = New-Object System.Drawing.Point(200, 95)
$lblVendor.AutoSize = $true
$panelScanTop.Controls.Add($lblVendor)

$cboVendor = New-Object System.Windows.Forms.ComboBox
$cboVendor.DropDownStyle = 'DropDownList'
$cboVendor.Location = New-Object System.Drawing.Point(255, 92)
$cboVendor.Size = New-Object System.Drawing.Size(120, 23)
$cboVendor.Items.AddRange(@('Auto-Detect', 'Hirschmann', 'Cisco'))
$cboVendor.SelectedIndex = 0
$panelScanTop.Controls.Add($cboVendor)

$btnSelectAll = New-Object System.Windows.Forms.Button
$btnSelectAll.Text = "Select All"
$btnSelectAll.Location = New-Object System.Drawing.Point(5, 127)
$btnSelectAll.Size = New-Object System.Drawing.Size(90, 27)
$panelScanTop.Controls.Add($btnSelectAll)

$btnSelectNone = New-Object System.Windows.Forms.Button
$btnSelectNone.Text = "Select None"
$btnSelectNone.Location = New-Object System.Drawing.Point(100, 127)
$btnSelectNone.Size = New-Object System.Drawing.Size(90, 27)
$panelScanTop.Controls.Add($btnSelectNone)

$btnIdentify = New-Object System.Windows.Forms.Button
$btnIdentify.Text = "Identify Selected"
$btnIdentify.Location = New-Object System.Drawing.Point(200, 127)
$btnIdentify.Size = New-Object System.Drawing.Size(120, 27)
$panelScanTop.Controls.Add($btnIdentify)

$btnWatchdog = New-Object System.Windows.Forms.Button
$btnWatchdog.Text = "Start Watchdog"
$btnWatchdog.Location = New-Object System.Drawing.Point(330, 127)
$btnWatchdog.Size = New-Object System.Drawing.Size(120, 27)
$panelScanTop.Controls.Add($btnWatchdog)

$dgvScan = New-Object System.Windows.Forms.DataGridView
$dgvScan.Dock = 'Fill'
$dgvScan.AllowUserToAddRows = $false
$dgvScan.AllowUserToDeleteRows = $false
$dgvScan.SelectionMode = 'FullRowSelect'
$dgvScan.RowHeadersVisible = $false
$dgvScan.AutoSizeColumnsMode = 'Fill'
$dgvScan.BackgroundColor = [System.Drawing.SystemColors]::Window
$dgvScan.DefaultCellStyle.SelectionBackColor = $dgvScan.DefaultCellStyle.BackColor
$dgvScan.DefaultCellStyle.SelectionForeColor = $dgvScan.DefaultCellStyle.ForeColor

$colCheck = New-Object System.Windows.Forms.DataGridViewCheckBoxColumn
$colCheck.Name = "Selected"
$colCheck.HeaderText = ""
$colCheck.Width = 30
$colCheck.FillWeight = 10
$dgvScan.Columns.Add($colCheck) | Out-Null

$colPing = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colPing.Name = "Ping"
$colPing.HeaderText = "Ping"
$colPing.ReadOnly = $true
$colPing.Width = 40
$colPing.FillWeight = 8
$colPing.DefaultCellStyle.Alignment = 'MiddleCenter'
$colPing.DefaultCellStyle.Font = New-Object System.Drawing.Font("Segoe UI", 12)
$dgvScan.Columns.Add($colPing) | Out-Null

$colIP = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colIP.Name = "IP"
$colIP.HeaderText = "IP Address"
$colIP.ReadOnly = $true
$colIP.FillWeight = 25
$dgvScan.Columns.Add($colIP) | Out-Null

$colPort = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colPort.Name = "Port"
$colPort.HeaderText = "Port"
$colPort.ReadOnly = $true
$colPort.FillWeight = 14
$dgvScan.Columns.Add($colPort) | Out-Null

$colType = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colType.Name = "Type"
$colType.HeaderText = "Type"
$colType.ReadOnly = $true
$colType.FillWeight = 20
$dgvScan.Columns.Add($colType) | Out-Null

$colHostname = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colHostname.Name = "Hostname"
$colHostname.HeaderText = "Hostname"
$colHostname.ReadOnly = $true
$colHostname.FillWeight = 25
$dgvScan.Columns.Add($colHostname) | Out-Null

$colModel = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colModel.Name = "Model"
$colModel.HeaderText = "Model"
$colModel.ReadOnly = $true
$colModel.FillWeight = 25
$dgvScan.Columns.Add($colModel) | Out-Null

$colStatus = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colStatus.Name = "Status"
$colStatus.HeaderText = "Status"
$colStatus.ReadOnly = $true
$colStatus.FillWeight = 20
$dgvScan.Columns.Add($colStatus) | Out-Null

# Right-click context menu to override vendor per-device
$ctxMenuScan = New-Object System.Windows.Forms.ContextMenuStrip
$ctxSetHirschmann = New-Object System.Windows.Forms.ToolStripMenuItem
$ctxSetHirschmann.Text = "Set Vendor: Hirschmann"
$ctxSetCisco = New-Object System.Windows.Forms.ToolStripMenuItem
$ctxSetCisco.Text = "Set Vendor: Cisco"
$ctxSetAutoDetect = New-Object System.Windows.Forms.ToolStripMenuItem
$ctxSetAutoDetect.Text = "Set Vendor: Auto-Detect (clear override)"
$ctxMenuScan.Items.AddRange(@($ctxSetHirschmann, $ctxSetCisco, $ctxSetAutoDetect))
$dgvScan.ContextMenuStrip = $ctxMenuScan

$ctxSetHirschmann.Add_Click({
    foreach ($row in $dgvScan.SelectedRows) {
        $row.Cells["Type"].Value = "Hirschmann"
        $ip = $row.Cells["IP"].Value
        for ($j = 0; $j -lt $script:devices.Count; $j++) {
            if ($script:devices[$j].IP -eq $ip) {
                $script:devices[$j].Type = "Hirschmann"
                if (-not $script:devices[$j].Status -or $script:devices[$j].Status -notmatch 'Identified') {
                    $script:devices[$j].Status = "Identified (Manual: Hirschmann)"
                }
                break
            }
        }
        $row.Cells["Status"].Value = "Identified (Manual: Hirschmann)"
    }
})

$ctxSetCisco.Add_Click({
    foreach ($row in $dgvScan.SelectedRows) {
        $row.Cells["Type"].Value = "Cisco"
        $ip = $row.Cells["IP"].Value
        for ($j = 0; $j -lt $script:devices.Count; $j++) {
            if ($script:devices[$j].IP -eq $ip) {
                $script:devices[$j].Type = "Cisco"
                if (-not $script:devices[$j].Status -or $script:devices[$j].Status -notmatch 'Identified') {
                    $script:devices[$j].Status = "Identified (Manual: Cisco)"
                }
                break
            }
        }
        $row.Cells["Status"].Value = "Identified (Manual: Cisco)"
    }
})

$ctxSetAutoDetect.Add_Click({
    foreach ($row in $dgvScan.SelectedRows) {
        $row.Cells["Type"].Value = ""
        $ip = $row.Cells["IP"].Value
        for ($j = 0; $j -lt $script:devices.Count; $j++) {
            if ($script:devices[$j].IP -eq $ip) {
                $script:devices[$j].Type = ""
                $script:devices[$j].Status = "Vendor cleared - re-identify"
                break
            }
        }
        $row.Cells["Status"].Value = "Vendor cleared - re-identify"
    }
})

$tabScan.Controls.Add($dgvScan)
$tabScan.Controls.SetChildIndex($dgvScan, 0)

# ---------------------------------------------------------------------------
# Tab 2: Credentials
# ---------------------------------------------------------------------------
$tabCreds = New-Object System.Windows.Forms.TabPage
$tabCreds.Text = "Credentials"
$tabCreds.Padding = New-Object System.Windows.Forms.Padding(8)
$tabControl.TabPages.Add($tabCreds)

$panelCredTop = New-Object System.Windows.Forms.Panel
$panelCredTop.Dock = 'Top'
$panelCredTop.Height = 110
$tabCreds.Controls.Add($panelCredTop)

$lblUser = New-Object System.Windows.Forms.Label
$lblUser.Text = "Username:"
$lblUser.Location = New-Object System.Drawing.Point(5, 12)
$lblUser.AutoSize = $true
$panelCredTop.Controls.Add($lblUser)

$txtUsername = New-Object System.Windows.Forms.TextBox
$txtUsername.Location = New-Object System.Drawing.Point(110, 9)
$txtUsername.Size = New-Object System.Drawing.Size(180, 23)
$panelCredTop.Controls.Add($txtUsername)

$lblPass = New-Object System.Windows.Forms.Label
$lblPass.Text = "Password:"
$lblPass.Location = New-Object System.Drawing.Point(5, 42)
$lblPass.AutoSize = $true
$panelCredTop.Controls.Add($lblPass)

$txtPassword = New-Object System.Windows.Forms.TextBox
$txtPassword.Location = New-Object System.Drawing.Point(110, 39)
$txtPassword.Size = New-Object System.Drawing.Size(180, 23)
$txtPassword.UseSystemPasswordChar = $true
$panelCredTop.Controls.Add($txtPassword)

$lblEnable = New-Object System.Windows.Forms.Label
$lblEnable.Text = "Enable Password:"
$lblEnable.Location = New-Object System.Drawing.Point(5, 72)
$lblEnable.AutoSize = $true
$panelCredTop.Controls.Add($lblEnable)

$txtEnablePass = New-Object System.Windows.Forms.TextBox
$txtEnablePass.Location = New-Object System.Drawing.Point(110, 69)
$txtEnablePass.Size = New-Object System.Drawing.Size(180, 23)
$txtEnablePass.UseSystemPasswordChar = $true
$panelCredTop.Controls.Add($txtEnablePass)

$btnAddCred = New-Object System.Windows.Forms.Button
$btnAddCred.Text = "Add"
$btnAddCred.Location = New-Object System.Drawing.Point(310, 9)
$btnAddCred.Size = New-Object System.Drawing.Size(80, 27)
$panelCredTop.Controls.Add($btnAddCred)

$btnRemoveCred = New-Object System.Windows.Forms.Button
$btnRemoveCred.Text = "Remove"
$btnRemoveCred.Location = New-Object System.Drawing.Point(310, 42)
$btnRemoveCred.Size = New-Object System.Drawing.Size(80, 27)
$panelCredTop.Controls.Add($btnRemoveCred)

$btnSaveCreds = New-Object System.Windows.Forms.Button
$btnSaveCreds.Text = "Save"
$btnSaveCreds.Location = New-Object System.Drawing.Point(310, 75)
$btnSaveCreds.Size = New-Object System.Drawing.Size(80, 27)
$panelCredTop.Controls.Add($btnSaveCreds)

$btnLoadCreds = New-Object System.Windows.Forms.Button
$btnLoadCreds.Text = "Load"
$btnLoadCreds.Location = New-Object System.Drawing.Point(400, 75)
$btnLoadCreds.Size = New-Object System.Drawing.Size(80, 27)
$panelCredTop.Controls.Add($btnLoadCreds)

$chkShowPasswords = New-Object System.Windows.Forms.CheckBox
$chkShowPasswords.Text = "Show Passwords"
$chkShowPasswords.Location = New-Object System.Drawing.Point(500, 12)
$chkShowPasswords.AutoSize = $true
$panelCredTop.Controls.Add($chkShowPasswords)

$chkShowPasswords.Add_CheckedChanged({
    $script:showPasswords = $chkShowPasswords.Checked
    for ($i = 0; $i -lt $dgvCreds.Rows.Count; $i++) {
        $cred = $script:credentials[$i]
        if ($script:showPasswords) {
            $dgvCreds.Rows[$i].Cells["Password"].Value = $cred.Password
            $dgvCreds.Rows[$i].Cells["EnablePassword"].Value = $cred.EnablePassword
        } else {
            $pass = $cred.Password
            $enable = $cred.EnablePassword
            $dgvCreds.Rows[$i].Cells["Password"].Value = if ($pass.Length -gt 0) { "*" * [Math]::Min($pass.Length, 8) } else { "" }
            $dgvCreds.Rows[$i].Cells["EnablePassword"].Value = if ($enable.Length -gt 0) { "*" * [Math]::Min($enable.Length, 8) } else { "" }
        }
    }
})

$dgvCreds = New-Object System.Windows.Forms.DataGridView
$dgvCreds.Dock = 'Fill'
$dgvCreds.AllowUserToAddRows = $false
$dgvCreds.AllowUserToDeleteRows = $false
$dgvCreds.SelectionMode = 'FullRowSelect'
$dgvCreds.RowHeadersVisible = $false
$dgvCreds.AutoSizeColumnsMode = 'Fill'
$dgvCreds.BackgroundColor = [System.Drawing.SystemColors]::Window
$dgvCreds.ReadOnly = $true

$colCredUser = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colCredUser.Name = "Username"
$colCredUser.HeaderText = "Username"
$colCredUser.FillWeight = 30
$dgvCreds.Columns.Add($colCredUser) | Out-Null

$colCredPass = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colCredPass.Name = "Password"
$colCredPass.HeaderText = "Password"
$colCredPass.FillWeight = 30
$dgvCreds.Columns.Add($colCredPass) | Out-Null

$colCredEnable = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colCredEnable.Name = "EnablePassword"
$colCredEnable.HeaderText = "Enable Password"
$colCredEnable.FillWeight = 30
$dgvCreds.Columns.Add($colCredEnable) | Out-Null

$tabCreds.Controls.Add($dgvCreds)
$tabCreds.Controls.SetChildIndex($dgvCreds, 0)

# Auto-load saved credentials on startup
if (Test-Path $script:credFilePath) {
    try {
        $loaded = Import-EncryptedCredentials -FilePath $script:credFilePath
        foreach ($cred in $loaded) {
            $script:credentials.Add($cred) | Out-Null
            $displayPass = if ($cred.Password.Length -gt 0) { "*" * [Math]::Min($cred.Password.Length, 8) } else { "" }
            $displayEnable = if ($cred.EnablePassword.Length -gt 0) { "*" * [Math]::Min($cred.EnablePassword.Length, 8) } else { "" }
            $dgvCreds.Rows.Add($cred.Username, $displayPass, $displayEnable) | Out-Null
        }
    } catch {}
}

# ---------------------------------------------------------------------------
# Tab 3: Backup
# ---------------------------------------------------------------------------
$tabBackup = New-Object System.Windows.Forms.TabPage
$tabBackup.Text = "Backup"
$tabBackup.Padding = New-Object System.Windows.Forms.Padding(8)
$tabControl.TabPages.Add($tabBackup)

$panelBackupTop = New-Object System.Windows.Forms.Panel
$panelBackupTop.Dock = 'Top'
$panelBackupTop.Height = 75
$tabBackup.Controls.Add($panelBackupTop)

$lblOutputDir = New-Object System.Windows.Forms.Label
$lblOutputDir.Text = "Output Directory:"
$lblOutputDir.Location = New-Object System.Drawing.Point(5, 12)
$lblOutputDir.AutoSize = $true
$panelBackupTop.Controls.Add($lblOutputDir)

$btnOpenFolder = New-Object System.Windows.Forms.Button
$btnOpenFolder.Text = "Open Folder"
$btnOpenFolder.Size = New-Object System.Drawing.Size(90, 27)
$btnOpenFolder.Anchor = 'Top,Right'
$panelBackupTop.Controls.Add($btnOpenFolder)

$btnBrowse = New-Object System.Windows.Forms.Button
$btnBrowse.Text = "Browse..."
$btnBrowse.Size = New-Object System.Drawing.Size(80, 27)
$btnBrowse.Anchor = 'Top,Right'
$panelBackupTop.Controls.Add($btnBrowse)

$txtOutputDir = New-Object System.Windows.Forms.TextBox
$txtOutputDir.Location = New-Object System.Drawing.Point(115, 9)
$txtOutputDir.Size = New-Object System.Drawing.Size(500, 23)
$txtOutputDir.Anchor = 'Top,Left,Right'
$txtOutputDir.Text = [Environment]::GetFolderPath('Desktop')
$panelBackupTop.Controls.Add($txtOutputDir)

# Position Browse and Open Folder relative to the panel width
$btnBrowse.Location = New-Object System.Drawing.Point(($panelBackupTop.ClientSize.Width - 175), 7)
$btnOpenFolder.Location = New-Object System.Drawing.Point(($panelBackupTop.ClientSize.Width - 92), 7)
$txtOutputDir.Size = New-Object System.Drawing.Size(($panelBackupTop.ClientSize.Width - 290), 23)

$btnBackupSelected = New-Object System.Windows.Forms.Button
$btnBackupSelected.Text = "Backup Selected"
$btnBackupSelected.Location = New-Object System.Drawing.Point(5, 42)
$btnBackupSelected.Size = New-Object System.Drawing.Size(120, 27)
$panelBackupTop.Controls.Add($btnBackupSelected)

$btnBackupAll = New-Object System.Windows.Forms.Button
$btnBackupAll.Text = "Backup All"
$btnBackupAll.Location = New-Object System.Drawing.Point(130, 42)
$btnBackupAll.Size = New-Object System.Drawing.Size(90, 27)
$panelBackupTop.Controls.Add($btnBackupAll)

$btnBackupStop = New-Object System.Windows.Forms.Button
$btnBackupStop.Text = "Stop"
$btnBackupStop.Location = New-Object System.Drawing.Point(225, 42)
$btnBackupStop.Size = New-Object System.Drawing.Size(80, 27)
$btnBackupStop.Enabled = $false
$panelBackupTop.Controls.Add($btnBackupStop)

$progressBackup = New-Object System.Windows.Forms.ProgressBar
$progressBackup.Location = New-Object System.Drawing.Point(320, 44)
$progressBackup.Size = New-Object System.Drawing.Size(385, 22)
$progressBackup.Anchor = 'Top,Left,Right'
$panelBackupTop.Controls.Add($progressBackup)

# Split panel for backup grid and log
$splitBackup = New-Object System.Windows.Forms.SplitContainer
$splitBackup.Dock = 'Fill'
$splitBackup.Orientation = 'Horizontal'
$splitBackup.SplitterDistance = 250
$tabBackup.Controls.Add($splitBackup)
$tabBackup.Controls.SetChildIndex($splitBackup, 0)

$dgvBackup = New-Object System.Windows.Forms.DataGridView
$dgvBackup.Dock = 'Fill'
$dgvBackup.AllowUserToAddRows = $false
$dgvBackup.AllowUserToDeleteRows = $false
$dgvBackup.SelectionMode = 'FullRowSelect'
$dgvBackup.RowHeadersVisible = $false
$dgvBackup.AutoSizeColumnsMode = 'Fill'
$dgvBackup.BackgroundColor = [System.Drawing.SystemColors]::Window
$dgvBackup.ReadOnly = $true

$colBkIP = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colBkIP.Name = "IP"
$colBkIP.HeaderText = "IP Address"
$colBkIP.FillWeight = 20
$dgvBackup.Columns.Add($colBkIP) | Out-Null

$colBkType = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colBkType.Name = "Type"
$colBkType.HeaderText = "Type"
$colBkType.FillWeight = 15
$dgvBackup.Columns.Add($colBkType) | Out-Null

$colBkHost = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colBkHost.Name = "Hostname"
$colBkHost.HeaderText = "Hostname"
$colBkHost.FillWeight = 20
$dgvBackup.Columns.Add($colBkHost) | Out-Null

$colBkStatus = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colBkStatus.Name = "Status"
$colBkStatus.HeaderText = "Status"
$colBkStatus.FillWeight = 20
$dgvBackup.Columns.Add($colBkStatus) | Out-Null

$colBkFile = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colBkFile.Name = "Filename"
$colBkFile.HeaderText = "Filename"
$colBkFile.FillWeight = 30
$dgvBackup.Columns.Add($colBkFile) | Out-Null

$splitBackup.Panel1.Controls.Add($dgvBackup)

$rtbLog = New-Object System.Windows.Forms.RichTextBox
$rtbLog.Dock = 'Fill'
$rtbLog.ReadOnly = $true
$rtbLog.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$rtbLog.ForeColor = [System.Drawing.Color]::LightGreen
$rtbLog.Font = New-Object System.Drawing.Font("Consolas", 9)
$splitBackup.Panel2.Controls.Add($rtbLog)

# ---------------------------------------------------------------------------
# Tab 4: Audit
# ---------------------------------------------------------------------------
$tabAudit = New-Object System.Windows.Forms.TabPage
$tabAudit.Text = "Audit"
$tabAudit.Padding = New-Object System.Windows.Forms.Padding(8)
$tabControl.TabPages.Add($tabAudit)

# -- Audit top panel: output directory row --
$panelAuditTop = New-Object System.Windows.Forms.Panel
$panelAuditTop.Dock = 'Top'
$panelAuditTop.Height = 42
$tabAudit.Controls.Add($panelAuditTop)

$lblAuditDir = New-Object System.Windows.Forms.Label
$lblAuditDir.Text = "Output Directory:"
$lblAuditDir.Location = New-Object System.Drawing.Point(5, 12)
$lblAuditDir.AutoSize = $true
$panelAuditTop.Controls.Add($lblAuditDir)

$txtAuditDir = New-Object System.Windows.Forms.TextBox
$txtAuditDir.Location = New-Object System.Drawing.Point(115, 9)
$txtAuditDir.Size = New-Object System.Drawing.Size(500, 23)
$txtAuditDir.Anchor = 'Top,Left,Right'
$txtAuditDir.Text = [Environment]::GetFolderPath('Desktop')
$panelAuditTop.Controls.Add($txtAuditDir)

$btnAuditOpenFolder = New-Object System.Windows.Forms.Button
$btnAuditOpenFolder.Text = "Open Folder"
$btnAuditOpenFolder.Size = New-Object System.Drawing.Size(90, 27)
$btnAuditOpenFolder.Anchor = 'Top,Right'
$panelAuditTop.Controls.Add($btnAuditOpenFolder)

$btnAuditBrowse = New-Object System.Windows.Forms.Button
$btnAuditBrowse.Text = "Browse..."
$btnAuditBrowse.Size = New-Object System.Drawing.Size(80, 27)
$btnAuditBrowse.Anchor = 'Top,Right'
$panelAuditTop.Controls.Add($btnAuditBrowse)

$btnAuditBrowse.Location = New-Object System.Drawing.Point(($panelAuditTop.ClientSize.Width - 175), 7)
$btnAuditOpenFolder.Location = New-Object System.Drawing.Point(($panelAuditTop.ClientSize.Width - 92), 7)
$txtAuditDir.Size = New-Object System.Drawing.Size(($panelAuditTop.ClientSize.Width - 290), 23)

# -- Audit controls panel: command buttons, run/stop, progress --
$panelAuditCtrl = New-Object System.Windows.Forms.Panel
$panelAuditCtrl.Dock = 'Top'
$panelAuditCtrl.Height = 40
$tabAudit.Controls.Add($panelAuditCtrl)

$btnAuditCiscoList = New-Object System.Windows.Forms.Button
$btnAuditCiscoList.Text = "Cisco Commands..."
$btnAuditCiscoList.Location = New-Object System.Drawing.Point(5, 7)
$btnAuditCiscoList.Size = New-Object System.Drawing.Size(130, 27)
$panelAuditCtrl.Controls.Add($btnAuditCiscoList)

$btnAuditHirschList = New-Object System.Windows.Forms.Button
$btnAuditHirschList.Text = "Hirschmann Commands..."
$btnAuditHirschList.Location = New-Object System.Drawing.Point(140, 7)
$btnAuditHirschList.Size = New-Object System.Drawing.Size(155, 27)
$panelAuditCtrl.Controls.Add($btnAuditHirschList)

$btnAuditClearCmds = New-Object System.Windows.Forms.Button
$btnAuditClearCmds.Text = "Clear"
$btnAuditClearCmds.Location = New-Object System.Drawing.Point(300, 7)
$btnAuditClearCmds.Size = New-Object System.Drawing.Size(60, 27)
$panelAuditCtrl.Controls.Add($btnAuditClearCmds)

$btnAuditRun = New-Object System.Windows.Forms.Button
$btnAuditRun.Text = "Run Audit"
$btnAuditRun.Location = New-Object System.Drawing.Point(380, 7)
$btnAuditRun.Size = New-Object System.Drawing.Size(90, 27)
$panelAuditCtrl.Controls.Add($btnAuditRun)

$btnAuditStop = New-Object System.Windows.Forms.Button
$btnAuditStop.Text = "Stop"
$btnAuditStop.Location = New-Object System.Drawing.Point(475, 7)
$btnAuditStop.Size = New-Object System.Drawing.Size(70, 27)
$btnAuditStop.Enabled = $false
$panelAuditCtrl.Controls.Add($btnAuditStop)

$progressAudit = New-Object System.Windows.Forms.ProgressBar
$progressAudit.Location = New-Object System.Drawing.Point(555, 9)
$progressAudit.Size = New-Object System.Drawing.Size(350, 22)
$progressAudit.Anchor = 'Top,Left,Right'
$panelAuditCtrl.Controls.Add($progressAudit)

# Ensure dock order: panelAuditTop on top, panelAuditCtrl below, then split fills rest
$tabAudit.Controls.SetChildIndex($panelAuditCtrl, 0)
$tabAudit.Controls.SetChildIndex($panelAuditTop, 0)

# -- Audit split: left = commands text box, right = split (grid + log) --
$splitAudit = New-Object System.Windows.Forms.SplitContainer
$splitAudit.Dock = 'Fill'
$splitAudit.Orientation = 'Vertical'
$splitAudit.SplitterDistance = 280
$tabAudit.Controls.Add($splitAudit)
$tabAudit.Controls.SetChildIndex($splitAudit, 0)

# Left panel: command entry
$lblAuditCmds = New-Object System.Windows.Forms.Label
$lblAuditCmds.Text = "Show Commands (one per line, max 100):"
$lblAuditCmds.Dock = 'Top'
$lblAuditCmds.Height = 20
$splitAudit.Panel1.Controls.Add($lblAuditCmds)

$txtAuditCmds = New-Object System.Windows.Forms.TextBox
$txtAuditCmds.Dock = 'Fill'
$txtAuditCmds.Multiline = $true
$txtAuditCmds.ScrollBars = 'Vertical'
$txtAuditCmds.WordWrap = $false
$txtAuditCmds.Font = New-Object System.Drawing.Font("Consolas", 9)
$txtAuditCmds.AcceptsReturn = $true
$splitAudit.Panel1.Controls.Add($txtAuditCmds)
$splitAudit.Panel1.Controls.SetChildIndex($txtAuditCmds, 0)

# Right panel: split between results grid and log
$splitAuditRight = New-Object System.Windows.Forms.SplitContainer
$splitAuditRight.Dock = 'Fill'
$splitAuditRight.Orientation = 'Horizontal'
$splitAuditRight.SplitterDistance = 200
$splitAudit.Panel2.Controls.Add($splitAuditRight)

# Results grid
$dgvAudit = New-Object System.Windows.Forms.DataGridView
$dgvAudit.Dock = 'Fill'
$dgvAudit.AllowUserToAddRows = $false
$dgvAudit.AllowUserToDeleteRows = $false
$dgvAudit.SelectionMode = 'FullRowSelect'
$dgvAudit.RowHeadersVisible = $false
$dgvAudit.AutoSizeColumnsMode = 'Fill'
$dgvAudit.BackgroundColor = [System.Drawing.SystemColors]::Window
$dgvAudit.ReadOnly = $true

$colAuIP = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colAuIP.Name = "IP"
$colAuIP.HeaderText = "IP Address"
$colAuIP.FillWeight = 20
$dgvAudit.Columns.Add($colAuIP) | Out-Null

$colAuType = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colAuType.Name = "Type"
$colAuType.HeaderText = "Type"
$colAuType.FillWeight = 15
$dgvAudit.Columns.Add($colAuType) | Out-Null

$colAuHost = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colAuHost.Name = "Hostname"
$colAuHost.HeaderText = "Hostname"
$colAuHost.FillWeight = 20
$dgvAudit.Columns.Add($colAuHost) | Out-Null

$colAuCmds = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colAuCmds.Name = "Commands"
$colAuCmds.HeaderText = "Commands"
$colAuCmds.FillWeight = 10
$dgvAudit.Columns.Add($colAuCmds) | Out-Null

$colAuStatus = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colAuStatus.Name = "Status"
$colAuStatus.HeaderText = "Status"
$colAuStatus.FillWeight = 18
$dgvAudit.Columns.Add($colAuStatus) | Out-Null

$colAuFile = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colAuFile.Name = "Filename"
$colAuFile.HeaderText = "Filename"
$colAuFile.FillWeight = 25
$dgvAudit.Columns.Add($colAuFile) | Out-Null

$splitAuditRight.Panel1.Controls.Add($dgvAudit)

# Audit log
$rtbAuditLog = New-Object System.Windows.Forms.RichTextBox
$rtbAuditLog.Dock = 'Fill'
$rtbAuditLog.ReadOnly = $true
$rtbAuditLog.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$rtbAuditLog.ForeColor = [System.Drawing.Color]::LightGreen
$rtbAuditLog.Font = New-Object System.Drawing.Font("Consolas", 9)
$splitAuditRight.Panel2.Controls.Add($rtbAuditLog)

# ---------------------------------------------------------------------------
# Discovery Tab (HiDiscovery / HiView style)
# ---------------------------------------------------------------------------
$tabDiscovery = New-Object System.Windows.Forms.TabPage
$tabDiscovery.Text = "Discovery"
$tabDiscovery.Padding = New-Object System.Windows.Forms.Padding(6)
$tabControl.TabPages.Add($tabDiscovery)

# -- Discovery top panel: buttons --
$panelDiscTop = New-Object System.Windows.Forms.Panel
$panelDiscTop.Dock = 'Top'
$panelDiscTop.Height = 38
$tabDiscovery.Controls.Add($panelDiscTop)

$btnDiscScan = New-Object System.Windows.Forms.Button
$btnDiscScan.Text = "Scan"
$btnDiscScan.Location = New-Object System.Drawing.Point(8, 5)
$btnDiscScan.Size = New-Object System.Drawing.Size(75, 27)
$panelDiscTop.Controls.Add($btnDiscScan)

$btnDiscStop = New-Object System.Windows.Forms.Button
$btnDiscStop.Text = "Stop"
$btnDiscStop.Location = New-Object System.Drawing.Point(90, 5)
$btnDiscStop.Size = New-Object System.Drawing.Size(75, 27)
$btnDiscStop.Enabled = $false
$panelDiscTop.Controls.Add($btnDiscStop)

$lblDiscTimeout = New-Object System.Windows.Forms.Label
$lblDiscTimeout.Text = "Timeout (s):"
$lblDiscTimeout.Location = New-Object System.Drawing.Point(185, 10)
$lblDiscTimeout.AutoSize = $true
$panelDiscTop.Controls.Add($lblDiscTimeout)

$numDiscTimeout = New-Object System.Windows.Forms.NumericUpDown
$numDiscTimeout.Location = New-Object System.Drawing.Point(260, 7)
$numDiscTimeout.Size = New-Object System.Drawing.Size(55, 23)
$numDiscTimeout.Minimum = 1
$numDiscTimeout.Maximum = 30
$numDiscTimeout.Value = 5
$panelDiscTop.Controls.Add($numDiscTimeout)

$chkDiscSsh = New-Object System.Windows.Forms.CheckBox
$chkDiscSsh.Text = "SSH Enrich"
$chkDiscSsh.Location = New-Object System.Drawing.Point(330, 8)
$chkDiscSsh.AutoSize = $true
$chkDiscSsh.Checked = $false
$panelDiscTop.Controls.Add($chkDiscSsh)

# -- Discovery bottom panel: NIC selector + status --
$panelDiscBottom = New-Object System.Windows.Forms.Panel
$panelDiscBottom.Dock = 'Bottom'
$panelDiscBottom.Height = 30
$tabDiscovery.Controls.Add($panelDiscBottom)

$cboDiscNic = New-Object System.Windows.Forms.ComboBox
$cboDiscNic.DropDownStyle = 'DropDownList'
$cboDiscNic.Location = New-Object System.Drawing.Point(8, 4)
$cboDiscNic.Size = New-Object System.Drawing.Size(450, 23)
$panelDiscBottom.Controls.Add($cboDiscNic)

# Populate NIC selector with IPv4-capable interfaces
$nicInfoList = [System.Collections.ArrayList]::new()
$nics = [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() |
    Where-Object { $_.OperationalStatus -eq 'Up' -and $_.NetworkInterfaceType -ne 'Loopback' }
foreach ($nic in $nics) {
    $ipProps = $nic.GetIPProperties()
    $ipv4 = $ipProps.UnicastAddresses | Where-Object { $_.Address.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1
    if ($ipv4) {
        $nicLabel = "$($ipv4.Address) / $($ipv4.PrefixLength): $($nic.Name)"
        $null = $cboDiscNic.Items.Add($nicLabel)
        $null = $nicInfoList.Add(@{ Label = $nicLabel; IP = $ipv4.Address.ToString(); Nic = $nic })
    }
}
$cboDiscNic.Tag = $nicInfoList
if ($cboDiscNic.Items.Count -gt 0) { $cboDiscNic.SelectedIndex = 0 }

$progressDisc = New-Object System.Windows.Forms.ProgressBar
$progressDisc.Location = New-Object System.Drawing.Point(465, 4)
$progressDisc.Size = New-Object System.Drawing.Size(150, 20)
$progressDisc.Style = 'Marquee'
$progressDisc.MarqueeAnimationSpeed = 0
$panelDiscBottom.Controls.Add($progressDisc)

$lblDiscStatus = New-Object System.Windows.Forms.Label
$lblDiscStatus.Location = New-Object System.Drawing.Point(622, 6)
$lblDiscStatus.Size = New-Object System.Drawing.Size(400, 18)
$lblDiscStatus.Text = "Ready. HiDiscovery v2 protocol."
$panelDiscBottom.Controls.Add($lblDiscStatus)

# -- Discovery main split container --
$splitDisc = New-Object System.Windows.Forms.SplitContainer
$splitDisc.Dock = 'Fill'
$splitDisc.Orientation = 'Horizontal'
$splitDisc.SplitterDistance = 280
$tabDiscovery.Controls.Add($splitDisc)
$tabDiscovery.Controls.SetChildIndex($splitDisc, 0)

# -- Upper split: device grid + management panel --
$splitDiscUpper = New-Object System.Windows.Forms.SplitContainer
$splitDiscUpper.Dock = 'Fill'
$splitDiscUpper.Orientation = 'Horizontal'
$splitDiscUpper.SplitterDistance = 180
$splitDisc.Panel1.Controls.Add($splitDiscUpper)

# -- Device Grid --
$dgvDiscovery = New-Object System.Windows.Forms.DataGridView
$dgvDiscovery.Dock = 'Fill'
$dgvDiscovery.AllowUserToAddRows = $false
$dgvDiscovery.AllowUserToDeleteRows = $false
$dgvDiscovery.ReadOnly = $false
$dgvDiscovery.SelectionMode = 'FullRowSelect'
$dgvDiscovery.MultiSelect = $false
$dgvDiscovery.RowHeadersVisible = $false
$dgvDiscovery.AutoSizeColumnsMode = 'Fill'
$dgvDiscovery.BackgroundColor = [System.Drawing.Color]::White
$dgvDiscovery.BorderStyle = 'None'
$dgvDiscovery.AllowUserToResizeRows = $false
$dgvDiscovery.EditMode = 'EditOnEnter'

$colDiscSel = New-Object System.Windows.Forms.DataGridViewCheckBoxColumn
$colDiscSel.Name = "Signal"
$colDiscSel.HeaderText = "Signal"
$colDiscSel.Width = 45
$colDiscSel.FillWeight = 6
$colDiscSel.ReadOnly = $false
$null = $dgvDiscovery.Columns.Add($colDiscSel)

$colDiscCfg = New-Object System.Windows.Forms.DataGridViewCheckBoxColumn
$colDiscCfg.Name = "Configured"
$colDiscCfg.HeaderText = "Configured"
$colDiscCfg.Width = 65
$colDiscCfg.FillWeight = 8
$colDiscCfg.ReadOnly = $true
$null = $dgvDiscovery.Columns.Add($colDiscCfg)

$colDiscPwd = New-Object System.Windows.Forms.DataGridViewCheckBoxColumn
$colDiscPwd.Name = "PasswordSet"
$colDiscPwd.HeaderText = "Password"
$colDiscPwd.Width = 60
$colDiscPwd.FillWeight = 8
$colDiscPwd.ReadOnly = $true
$null = $dgvDiscovery.Columns.Add($colDiscPwd)

$colDiscMAC = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colDiscMAC.Name = "MACAddress"
$colDiscMAC.HeaderText = "MAC Address"
$colDiscMAC.FillWeight = 16
$colDiscMAC.ReadOnly = $true
$null = $dgvDiscovery.Columns.Add($colDiscMAC)

$colDiscIP = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colDiscIP.Name = "IPAddress"
$colDiscIP.HeaderText = "IP Address"
$colDiscIP.FillWeight = 14
$colDiscIP.ReadOnly = $true
$null = $dgvDiscovery.Columns.Add($colDiscIP)

$colDiscMask = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colDiscMask.Name = "Netmask"
$colDiscMask.HeaderText = "Netmask"
$colDiscMask.FillWeight = 14
$colDiscMask.ReadOnly = $true
$null = $dgvDiscovery.Columns.Add($colDiscMask)

$colDiscGw = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colDiscGw.Name = "Gateway"
$colDiscGw.HeaderText = "Gateway"
$colDiscGw.FillWeight = 14
$colDiscGw.ReadOnly = $true
$null = $dgvDiscovery.Columns.Add($colDiscGw)

$colDiscHostname = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colDiscHostname.Name = "Hostname"
$colDiscHostname.HeaderText = "Hostname"
$colDiscHostname.FillWeight = 14
$colDiscHostname.ReadOnly = $true
$null = $dgvDiscovery.Columns.Add($colDiscHostname)

$colDiscType = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colDiscType.Name = "Type"
$colDiscType.HeaderText = "Type"
$colDiscType.FillWeight = 6
$colDiscType.ReadOnly = $true
$null = $dgvDiscovery.Columns.Add($colDiscType)

$colDiscProduct = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colDiscProduct.Name = "Product"
$colDiscProduct.HeaderText = "Product"
$colDiscProduct.FillWeight = 22
$colDiscProduct.ReadOnly = $true
$null = $dgvDiscovery.Columns.Add($colDiscProduct)

$colDiscFirmware = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colDiscFirmware.Name = "Firmware"
$colDiscFirmware.HeaderText = "Firmware"
$colDiscFirmware.FillWeight = 18
$colDiscFirmware.ReadOnly = $true
$null = $dgvDiscovery.Columns.Add($colDiscFirmware)

# Hidden columns for internal data
$colDiscSerial = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colDiscSerial.Name = "Serial"
$colDiscSerial.HeaderText = "Serial"
$colDiscSerial.Visible = $false
$null = $dgvDiscovery.Columns.Add($colDiscSerial)

$splitDiscUpper.Panel1.Controls.Add($dgvDiscovery)

# -- Selection buttons panel between grid and management --
$panelDiscSelect = New-Object System.Windows.Forms.Panel
$panelDiscSelect.Dock = 'Bottom'
$panelDiscSelect.Height = 30
$splitDiscUpper.Panel1.Controls.Add($panelDiscSelect)

$btnDiscSelectAll = New-Object System.Windows.Forms.Button
$btnDiscSelectAll.Text = "Select All"
$btnDiscSelectAll.Location = New-Object System.Drawing.Point(8, 2)
$btnDiscSelectAll.Size = New-Object System.Drawing.Size(80, 25)
$panelDiscSelect.Controls.Add($btnDiscSelectAll)

$btnDiscSelectNone = New-Object System.Windows.Forms.Button
$btnDiscSelectNone.Text = "Select None"
$btnDiscSelectNone.Location = New-Object System.Drawing.Point(95, 2)
$btnDiscSelectNone.Size = New-Object System.Drawing.Size(85, 25)
$panelDiscSelect.Controls.Add($btnDiscSelectNone)

# -- Management GroupBox --
$grpDiscManage = New-Object System.Windows.Forms.GroupBox
$grpDiscManage.Text = "Device Management"
$grpDiscManage.Dock = 'Fill'
$grpDiscManage.Padding = New-Object System.Windows.Forms.Padding(8)
$splitDiscUpper.Panel2.Controls.Add($grpDiscManage)

# Row 1: IP assignment
$lblDiscNewIP = New-Object System.Windows.Forms.Label
$lblDiscNewIP.Text = "New IP:"
$lblDiscNewIP.Location = New-Object System.Drawing.Point(12, 22)
$lblDiscNewIP.AutoSize = $true
$grpDiscManage.Controls.Add($lblDiscNewIP)

$txtDiscNewIP = New-Object System.Windows.Forms.TextBox
$txtDiscNewIP.Location = New-Object System.Drawing.Point(72, 19)
$txtDiscNewIP.Size = New-Object System.Drawing.Size(130, 23)
$grpDiscManage.Controls.Add($txtDiscNewIP)

$lblDiscNewMask = New-Object System.Windows.Forms.Label
$lblDiscNewMask.Text = "Mask:"
$lblDiscNewMask.Location = New-Object System.Drawing.Point(212, 22)
$lblDiscNewMask.AutoSize = $true
$grpDiscManage.Controls.Add($lblDiscNewMask)

$txtDiscNewMask = New-Object System.Windows.Forms.TextBox
$txtDiscNewMask.Location = New-Object System.Drawing.Point(252, 19)
$txtDiscNewMask.Size = New-Object System.Drawing.Size(130, 23)
$txtDiscNewMask.Text = "255.255.255.0"
$grpDiscManage.Controls.Add($txtDiscNewMask)

$lblDiscNewGateway = New-Object System.Windows.Forms.Label
$lblDiscNewGateway.Text = "Gateway:"
$lblDiscNewGateway.Location = New-Object System.Drawing.Point(392, 22)
$lblDiscNewGateway.AutoSize = $true
$grpDiscManage.Controls.Add($lblDiscNewGateway)

$txtDiscNewGateway = New-Object System.Windows.Forms.TextBox
$txtDiscNewGateway.Location = New-Object System.Drawing.Point(455, 19)
$txtDiscNewGateway.Size = New-Object System.Drawing.Size(130, 23)
$grpDiscManage.Controls.Add($txtDiscNewGateway)

$lblDiscNewName = New-Object System.Windows.Forms.Label
$lblDiscNewName.Text = "Name:"
$lblDiscNewName.Location = New-Object System.Drawing.Point(595, 22)
$lblDiscNewName.AutoSize = $true
$grpDiscManage.Controls.Add($lblDiscNewName)

$txtDiscNewName = New-Object System.Windows.Forms.TextBox
$txtDiscNewName.Location = New-Object System.Drawing.Point(640, 19)
$txtDiscNewName.Size = New-Object System.Drawing.Size(130, 23)
$grpDiscManage.Controls.Add($txtDiscNewName)

# Row 2: Action buttons
$btnDiscApplyIP = New-Object System.Windows.Forms.Button
$btnDiscApplyIP.Text = "Apply IP Config"
$btnDiscApplyIP.Location = New-Object System.Drawing.Point(12, 50)
$btnDiscApplyIP.Size = New-Object System.Drawing.Size(110, 27)
$grpDiscManage.Controls.Add($btnDiscApplyIP)

$btnDiscFlashLED = New-Object System.Windows.Forms.Button
$btnDiscFlashLED.Text = "Flash LED"
$btnDiscFlashLED.Location = New-Object System.Drawing.Point(130, 50)
$btnDiscFlashLED.Size = New-Object System.Drawing.Size(85, 27)
$grpDiscManage.Controls.Add($btnDiscFlashLED)

$btnDiscOpenWeb = New-Object System.Windows.Forms.Button
$btnDiscOpenWeb.Text = "Open Web UI"
$btnDiscOpenWeb.Location = New-Object System.Drawing.Point(223, 50)
$btnDiscOpenWeb.Size = New-Object System.Drawing.Size(100, 27)
$grpDiscManage.Controls.Add($btnDiscOpenWeb)

# Row 2 continued: Password section
$lblDiscNewPwd = New-Object System.Windows.Forms.Label
$lblDiscNewPwd.Text = "New Password:"
$lblDiscNewPwd.Location = New-Object System.Drawing.Point(355, 54)
$lblDiscNewPwd.AutoSize = $true
$grpDiscManage.Controls.Add($lblDiscNewPwd)

$txtDiscNewPassword = New-Object System.Windows.Forms.TextBox
$txtDiscNewPassword.Location = New-Object System.Drawing.Point(450, 51)
$txtDiscNewPassword.Size = New-Object System.Drawing.Size(120, 23)
$txtDiscNewPassword.UseSystemPasswordChar = $true
$grpDiscManage.Controls.Add($txtDiscNewPassword)

$lblDiscNewEnable = New-Object System.Windows.Forms.Label
$lblDiscNewEnable.Text = "Enable Pwd:"
$lblDiscNewEnable.Location = New-Object System.Drawing.Point(580, 54)
$lblDiscNewEnable.AutoSize = $true
$grpDiscManage.Controls.Add($lblDiscNewEnable)

$txtDiscNewEnable = New-Object System.Windows.Forms.TextBox
$txtDiscNewEnable.Location = New-Object System.Drawing.Point(660, 51)
$txtDiscNewEnable.Size = New-Object System.Drawing.Size(120, 23)
$txtDiscNewEnable.UseSystemPasswordChar = $true
$grpDiscManage.Controls.Add($txtDiscNewEnable)

$btnDiscChangePwd = New-Object System.Windows.Forms.Button
$btnDiscChangePwd.Text = "Change Password"
$btnDiscChangePwd.Location = New-Object System.Drawing.Point(790, 50)
$btnDiscChangePwd.Size = New-Object System.Drawing.Size(120, 27)
$grpDiscManage.Controls.Add($btnDiscChangePwd)

# -- Lower split: Log --
$rtbDiscLog = New-Object System.Windows.Forms.RichTextBox
$rtbDiscLog.Dock = 'Fill'
$rtbDiscLog.ReadOnly = $true
$rtbDiscLog.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$rtbDiscLog.ForeColor = [System.Drawing.Color]::LightGreen
$rtbDiscLog.Font = New-Object System.Drawing.Font("Consolas", 9)
$splitDisc.Panel2.Controls.Add($rtbDiscLog)

# -- Selection button handlers --
$btnDiscSelectAll.Add_Click({
    $dgvDiscovery.CancelEdit()
    $dgvDiscovery.ClearSelection()
    for ($i = 0; $i -lt $dgvDiscovery.Rows.Count; $i++) {
        $dgvDiscovery.Rows[$i].Cells["Signal"].Value = $true
    }
    $dgvDiscovery.RefreshEdit()
    $dgvDiscovery.Invalidate()
})
$btnDiscSelectNone.Add_Click({
    $dgvDiscovery.CancelEdit()
    $dgvDiscovery.ClearSelection()
    for ($i = 0; $i -lt $dgvDiscovery.Rows.Count; $i++) {
        $dgvDiscovery.Rows[$i].Cells["Signal"].Value = $false
    }
    $dgvDiscovery.RefreshEdit()
    $dgvDiscovery.Invalidate()
})

# -- Commit checkbox changes immediately on click --
$dgvDiscovery.Add_CurrentCellDirtyStateChanged({
    if ($dgvDiscovery.IsCurrentCellDirty) {
        $null = $dgvDiscovery.CommitEdit([System.Windows.Forms.DataGridViewDataErrorContexts]::Commit)
    }
})

# -- Auto-populate management fields when selecting a device --
$dgvDiscovery.Add_SelectionChanged({
    if ($dgvDiscovery.SelectedRows.Count -gt 0) {
        $row = $dgvDiscovery.SelectedRows[0]
        $txtDiscNewIP.Text = $row.Cells["IPAddress"].Value
        $txtDiscNewMask.Text = $row.Cells["Netmask"].Value
        $txtDiscNewGateway.Text = $row.Cells["Gateway"].Value
        $txtDiscNewName.Text = $row.Cells["Hostname"].Value
    }
})

# ---------------------------------------------------------------------------
# Timer for UI updates from background threads
# ---------------------------------------------------------------------------
$uiTimer = New-Object System.Windows.Forms.Timer
$uiTimer.Interval = 500
$uiTimer.Add_Tick({
    # Update scan progress
    if ($sync.ScanTotal -gt 0) {
        $progressScan.Maximum = $sync.ScanTotal
        $progressScan.Value = [Math]::Min($sync.ScanProgress, $sync.ScanTotal)
    }
    if ($sync.ScanStatus) {
        $lblScanStatus.Text = $sync.ScanStatus
    }

    # Process scan results
    if ($sync.ScanComplete) {
        $sync.ScanComplete = $false
        $dgvScan.Rows.Clear()
        $script:devices.Clear()

        foreach ($r in $sync.ScanResults) {
            $script:devices.Add($r) | Out-Null
            $idx = $dgvScan.Rows.Add($true, [string][char]0x25CF, $r.IP, $r.Port, $r.Type, $r.Hostname, $r.Model, $r.Status)
            $dgvScan.Rows[$idx].Cells["Ping"].Style.ForeColor = [System.Drawing.Color]::Gray
            $dgvScan.Rows[$idx].Cells["Ping"].Style.SelectionForeColor = [System.Drawing.Color]::Gray
        }

        $btnScan.Enabled = $true
        $btnScanStop.Enabled = $false
        $btnIdentify.Enabled = $true
        $lblScanStatus.Text = "Scan complete. Found $($sync.ScanResults.Count) host(s) with $($script:connectionMethod)."
    }

    # Process identify results
    if ($sync.IdentifyStatus) {
        $lblScanStatus.Text = $sync.IdentifyStatus
    }
    if ($sync.IdentifyComplete) {
        $sync.IdentifyComplete = $false
        foreach ($r in $sync.IdentifyResults) {
            for ($i = 0; $i -lt $dgvScan.Rows.Count; $i++) {
                if ($dgvScan.Rows[$i].Cells["IP"].Value -eq $r.IP) {
                    $dgvScan.Rows[$i].Cells["Type"].Value = $r.Type
                    $dgvScan.Rows[$i].Cells["Hostname"].Value = $r.Hostname
                    $dgvScan.Rows[$i].Cells["Model"].Value = $r.Model
                    $dgvScan.Rows[$i].Cells["Status"].Value = $r.Status

                    # Update the device in our list
                    for ($j = 0; $j -lt $script:devices.Count; $j++) {
                        if ($script:devices[$j].IP -eq $r.IP) {
                            $script:devices[$j] = $r
                            break
                        }
                    }
                    break
                }
            }
        }
        $btnScan.Enabled = $true
        $btnIdentify.Enabled = $true
        $btnScanStop.Enabled = $false
        $lblScanStatus.Text = "Identification complete."
    }

    # Process backup results
    if ($sync.BackupStatus) {
        # Update backup grid
        $dgvBackup.Rows.Clear()
        foreach ($r in $sync.BackupResults) {
            $dgvBackup.Rows.Add($r.IP, $r.Type, $r.Hostname, $r.Status, $r.Filename) | Out-Null
        }
        if ($sync.BackupResults.Count -gt 0) {
            $done = @($sync.BackupResults | Where-Object { $_.Status -ne "Pending" -and $_.Status -ne "In Progress..." }).Count
            $progressBackup.Maximum = $sync.BackupResults.Count
            $progressBackup.Value = [Math]::Min($done, $sync.BackupResults.Count)
        }
    }
    if ($sync.BackupComplete) {
        $sync.BackupComplete = $false
        $btnBackupSelected.Enabled = $true
        $btnBackupAll.Enabled = $true
        $btnBackupStop.Enabled = $false

        # Final refresh of backup grid
        $dgvBackup.Rows.Clear()
        foreach ($r in $sync.BackupResults) {
            $dgvBackup.Rows.Add($r.IP, $r.Type, $r.Hostname, $r.Status, $r.Filename) | Out-Null
        }
        if ($sync.BackupResults.Count -gt 0) {
            $progressBackup.Maximum = $sync.BackupResults.Count
            $progressBackup.Value = $sync.BackupResults.Count
        }
    }

    # Process log entries
    $logEntries = $sync.BackupLog
    if ($logEntries.Count -gt $sync.LogIndex) {
        for ($i = $sync.LogIndex; $i -lt $logEntries.Count; $i++) {
            $entry = $logEntries[$i]
            $rtbLog.AppendText("$entry`n")
        }
        $sync.LogIndex = $logEntries.Count
        $rtbLog.ScrollToCaret()
    }

    # Process watchdog ping results
    if ($sync.WatchdogUpdated) {
        $sync.WatchdogUpdated = $false
        $pingResults = $sync.WatchdogResults
        for ($i = 0; $i -lt $dgvScan.Rows.Count; $i++) {
            $ip = $dgvScan.Rows[$i].Cells["IP"].Value
            if ($pingResults.ContainsKey($ip)) {
                $dgvScan.Rows[$i].Cells["Ping"].Value = [string][char]0x25CF
                if ($pingResults[$ip]) {
                    $dgvScan.Rows[$i].Cells["Ping"].Style.ForeColor = [System.Drawing.Color]::FromArgb(0, 200, 0)
                    $dgvScan.Rows[$i].Cells["Ping"].Style.SelectionForeColor = [System.Drawing.Color]::FromArgb(0, 200, 0)
                } else {
                    $dgvScan.Rows[$i].Cells["Ping"].Style.ForeColor = [System.Drawing.Color]::Red
                    $dgvScan.Rows[$i].Cells["Ping"].Style.SelectionForeColor = [System.Drawing.Color]::Red
                }
            }
        }
    }

    # Process audit results
    if ($sync.AuditStatus) {
        $dgvAudit.Rows.Clear()
        foreach ($r in $sync.AuditResults) {
            $dgvAudit.Rows.Add($r.IP, $r.Type, $r.Hostname, $r.Commands, $r.Status, $r.Filename) | Out-Null
        }
        if ($sync.AuditResults.Count -gt 0) {
            $done = @($sync.AuditResults | Where-Object { $_.Status -ne "Pending" -and $_.Status -ne "In Progress..." }).Count
            $progressAudit.Maximum = $sync.AuditResults.Count
            $progressAudit.Value = [Math]::Min($done, $sync.AuditResults.Count)
        }
    }
    if ($sync.AuditComplete) {
        $sync.AuditComplete = $false
        $btnAuditRun.Enabled = $true
        $btnAuditStop.Enabled = $false

        $dgvAudit.Rows.Clear()
        foreach ($r in $sync.AuditResults) {
            $dgvAudit.Rows.Add($r.IP, $r.Type, $r.Hostname, $r.Commands, $r.Status, $r.Filename) | Out-Null
        }
        if ($sync.AuditResults.Count -gt 0) {
            $progressAudit.Maximum = $sync.AuditResults.Count
            $progressAudit.Value = $sync.AuditResults.Count
        }

        # Show completion summary popup
        $auditTotal    = $sync.AuditResults.Count
        $auditSuccess  = @($sync.AuditResults | Where-Object { $_.Status -eq "Success" }).Count
        $auditFailed   = @($sync.AuditResults | Where-Object { $_.Status -match "^Failed" }).Count
        $auditCancelled = @($sync.AuditResults | Where-Object { $_.Status -eq "Pending" }).Count

        if ($auditFailed -eq 0 -and $auditCancelled -eq 0) {
            [System.Windows.Forms.MessageBox]::Show(
                "Audit completed successfully.`n`n" +
                "Devices audited: $auditSuccess of $auditTotal`n" +
                "All results saved to:`n$($txtAuditDir.Text)",
                "Audit Complete",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            )
        } elseif ($auditSuccess -eq 0 -and $auditCancelled -eq 0) {
            [System.Windows.Forms.MessageBox]::Show(
                "Audit finished with errors.`n`n" +
                "Failed: $auditFailed of $auditTotal device(s)`n`n" +
                "Check the log for details.",
                "Audit Failed",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
        } elseif ($auditCancelled -gt 0) {
            [System.Windows.Forms.MessageBox]::Show(
                "Audit was cancelled.`n`n" +
                "Succeeded: $auditSuccess`n" +
                "Failed: $auditFailed`n" +
                "Skipped: $auditCancelled`n`n" +
                "Completed results saved to:`n$($txtAuditDir.Text)",
                "Audit Cancelled",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            )
        } else {
            [System.Windows.Forms.MessageBox]::Show(
                "Audit completed with some errors.`n`n" +
                "Succeeded: $auditSuccess of $auditTotal`n" +
                "Failed: $auditFailed`n`n" +
                "Successful results saved to:`n$($txtAuditDir.Text)`n`n" +
                "Check the log for failure details.",
                "Audit Partial Success",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            )
        }
    }

    # Process audit log entries
    $auditLogEntries = $sync.AuditLog
    if ($auditLogEntries.Count -gt $sync.AuditLogIndex) {
        for ($i = $sync.AuditLogIndex; $i -lt $auditLogEntries.Count; $i++) {
            $entry = $auditLogEntries[$i]
            $rtbAuditLog.AppendText("$entry`n")
        }
        $sync.AuditLogIndex = $auditLogEntries.Count
        $rtbAuditLog.ScrollToCaret()
    }

    # Update Discovery status
    if ($sync.DiscoveryStatus) {
        $lblDiscStatus.Text = $sync.DiscoveryStatus
    }

    # Populate Discovery grid on completion
    if ($sync.DiscoveryComplete) {
        $sync.DiscoveryComplete = $false
        $btnDiscScan.Enabled = $true
        $btnDiscStop.Enabled = $false
        $progressDisc.MarqueeAnimationSpeed = 0
        $dgvDiscovery.Rows.Clear()
        foreach ($dev in $sync.DiscoveryResults) {
            $rowIdx = $dgvDiscovery.Rows.Add()
            $row = $dgvDiscovery.Rows[$rowIdx]
            $row.Cells["Signal"].Value = $false
            $row.Cells["Configured"].Value = ($dev.ConfigStatus -eq 1)
            $row.Cells["PasswordSet"].Value = ($dev.PasswordSet -eq 2)
            $row.Cells["MACAddress"].Value = $dev.MAC
            $row.Cells["IPAddress"].Value = $dev.IP
            $row.Cells["Netmask"].Value = $dev.Netmask
            $row.Cells["Gateway"].Value = $dev.Gateway
            $row.Cells["Hostname"].Value = $dev.Hostname
            $row.Cells["Type"].Value = "mgmt"
            $row.Cells["Product"].Value = $dev.Product
            $row.Cells["Firmware"].Value = $dev.Firmware
            $row.Cells["Serial"].Value = $dev.Serial
        }
        $lblDiscStatus.Text = "Found $($sync.DiscoveryResults.Count) device(s)."
    }

    # Process Discovery log entries
    $discLogEntries = $sync.DiscoveryLog
    if ($discLogEntries.Count -gt $sync.DiscoveryLogIndex) {
        for ($i = $sync.DiscoveryLogIndex; $i -lt $discLogEntries.Count; $i++) {
            $entry = $discLogEntries[$i]
            $rtbDiscLog.AppendText("$entry`n")
        }
        $sync.DiscoveryLogIndex = $discLogEntries.Count
        $rtbDiscLog.ScrollToCaret()
    }
})
$uiTimer.Start()

# ---------------------------------------------------------------------------
# Event Handlers
# ---------------------------------------------------------------------------

# -- Connection Method change --
$cboConnMethod.Add_SelectedIndexChanged({
    $script:connectionMethod = $cboConnMethod.SelectedItem.ToString()
})

# -- Vendor Override change --
$cboVendor.Add_SelectedIndexChanged({
    $script:vendorOverride = $cboVendor.SelectedItem.ToString()
})

# -- Scan button --
$btnScan.Add_Click({
    $cidr = $txtSubnet.Text.Trim()
    if (-not $cidr) {
        [System.Windows.Forms.MessageBox]::Show("Please enter a subnet in CIDR notation.", "Input Required")
        return
    }
    $ips = ConvertFrom-CIDR $cidr
    if ($ips.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("Invalid CIDR notation or no host IPs in range.", "Error")
        return
    }

    # Stop watchdog if running, since the grid is about to be cleared
    if ($script:watchdogRunning) {
        $sync.WatchdogCancel = $true
        $script:watchdogRunning = $false
        $btnWatchdog.Text = "Start Watchdog"
        if ($script:watchdogRunspace) {
            try {
                if ($script:watchdogRunspace.PS) { $script:watchdogRunspace.PS.Stop(); $script:watchdogRunspace.PS.Dispose() }
                if ($script:watchdogRunspace.RS) { $script:watchdogRunspace.RS.Close(); $script:watchdogRunspace.RS.Dispose() }
            } catch {}
            $script:watchdogRunspace = $null
        }
    }

    $sync.Cancel = $false
    $sync.ScanResults = @()
    $sync.ScanProgress = 0
    $sync.ScanTotal = $ips.Count
    $sync.ScanStatus = "Scanning $($ips.Count) IPs..."
    $sync.ScanComplete = $false

    $dgvScan.Rows.Clear()
    $script:devices.Clear()
    $btnScan.Enabled = $false
    $btnScanStop.Enabled = $true
    $btnIdentify.Enabled = $false
    $progressScan.Value = 0
    $progressScan.Maximum = $ips.Count

    # Create runspace pool for parallel scanning
    $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, 32, $script:sharedISS, [System.Management.Automation.Host.PSHost]$Host)
    $pool.Open()
    $script:runspacePool = $pool

    $method = $script:connectionMethod
    $scanPort = if ($method -eq "Telnet") { 23 } else { 22 }
    $portLabel = if ($method -eq "Telnet") { "Telnet(23)" } else { "SSH(22)" }

    $scanScript = {
        param($IP, $SyncHash, $Port)
        $result = @{ IP = $IP; Alive = $false; PortOpen = $false }
        try {
            $ping = New-Object System.Net.NetworkInformation.Ping
            $reply = $ping.Send($IP, 1000)
            if ($reply.Status -eq 'Success') {
                $result.Alive = $true
                try {
                    $client = New-Object System.Net.Sockets.TcpClient
                    $ar = $client.BeginConnect($IP, $Port, $null, $null)
                    $waited = $ar.AsyncWaitHandle.WaitOne(1500, $false)
                    if ($waited -and $client.Connected) {
                        $client.EndConnect($ar)
                        $result.PortOpen = $true
                    }
                    $client.Close()
                } catch {}
            }
            $ping.Dispose()
        } catch {}

        # Update progress atomically
        [System.Threading.Interlocked]::Increment([ref]$SyncHash.ScanProgress) | Out-Null
        return $result
    }

    # Launch all scan jobs
    $jobs = @()
    foreach ($ip in $ips) {
        $ps = [PowerShell]::Create()
        $ps.RunspacePool = $pool
        $ps.AddScript($scanScript).AddArgument($ip).AddArgument($sync).AddArgument($scanPort) | Out-Null
        $handle = $ps.BeginInvoke()
        $jobs += @{ PS = $ps; Handle = $handle }
    }

    # Collector runspace to wait for results
    $collectorRS = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace()
    $collectorRS.Open()

    $collectorPS = [PowerShell]::Create()
    $collectorPS.Runspace = $collectorRS
    $collectorPS.AddScript({
        param($Jobs, $SyncHash, $PortLabel, $MethodName)
        $results = @()
        foreach ($job in $Jobs) {
            try {
                $r = $job.PS.EndInvoke($job.Handle)
                if ($r -and $r.Count -gt 0) {
                    $item = $r[0]
                    if ($item.PortOpen) {
                        $results += @{
                            IP       = $item.IP
                            Port     = $PortLabel
                            Type     = ""
                            Hostname = ""
                            Model    = ""
                            Status   = "$MethodName Open"
                            ConnectionMethod = $MethodName
                        }
                    }
                }
            } catch {}
            $job.PS.Dispose()

            if ($SyncHash.Cancel) {
                $SyncHash.ScanStatus = "Scan cancelled."
                break
            }
        }

        # Sort results by IP
        $results = $results | Sort-Object { [Version]($_.IP) }
        $SyncHash.ScanResults = $results
        $SyncHash.ScanComplete = $true
    }).AddArgument($jobs).AddArgument($sync).AddArgument($portLabel).AddArgument($method) | Out-Null

    $collectorPS.BeginInvoke() | Out-Null
    $script:activeRunspace = @{ PS = $collectorPS; RS = $collectorRS; Pool = $pool }
})

# -- Scan Stop button --
$btnScanStop.Add_Click({
    $sync.Cancel = $true
    $lblScanStatus.Text = "Cancelling..."
    $btnScanStop.Enabled = $false
})

# -- Select All / Select None --
$btnSelectAll.Add_Click({
    foreach ($row in $dgvScan.Rows) { $row.Cells["Selected"].Value = $true }
})
$btnSelectNone.Add_Click({
    foreach ($row in $dgvScan.Rows) { $row.Cells["Selected"].Value = $false }
})

# -- Watchdog Toggle --
$btnWatchdog.Add_Click({
    if ($script:watchdogRunning) {
        # Stop the watchdog
        $sync.WatchdogCancel = $true
        $btnWatchdog.Text = "Start Watchdog"
        $script:watchdogRunning = $false

        # Clean up the runspace
        if ($script:watchdogRunspace) {
            try {
                if ($script:watchdogRunspace.PS) {
                    $script:watchdogRunspace.PS.Stop()
                    $script:watchdogRunspace.PS.Dispose()
                }
                if ($script:watchdogRunspace.RS) {
                    $script:watchdogRunspace.RS.Close()
                    $script:watchdogRunspace.RS.Dispose()
                }
            } catch {}
            $script:watchdogRunspace = $null
        }

        # Reset ping dots to gray
        for ($i = 0; $i -lt $dgvScan.Rows.Count; $i++) {
            $dgvScan.Rows[$i].Cells["Ping"].Style.ForeColor = [System.Drawing.Color]::Gray
            $dgvScan.Rows[$i].Cells["Ping"].Style.SelectionForeColor = [System.Drawing.Color]::Gray
        }
        return
    }

    # Start the watchdog
    if ($dgvScan.Rows.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No devices in the grid. Run a scan first.", "Info")
        return
    }

    $sync.WatchdogCancel = $false
    $sync.WatchdogResults = @{}
    $sync.WatchdogUpdated = $false
    $script:watchdogRunning = $true
    $btnWatchdog.Text = "Stop Watchdog"

    # Collect current IPs from the grid
    $ipList = @()
    for ($i = 0; $i -lt $dgvScan.Rows.Count; $i++) {
        $ipList += $dgvScan.Rows[$i].Cells["IP"].Value
    }

    $watchdogRS = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace()
    $watchdogRS.Open()

    $watchdogPS = [PowerShell]::Create()
    $watchdogPS.Runspace = $watchdogRS

    $watchdogPS.AddScript({
        param($IPs, $SyncHash, $IntervalMs)

        while (-not $SyncHash.WatchdogCancel) {
            $results = @{}
            foreach ($ip in $IPs) {
                if ($SyncHash.WatchdogCancel) { break }
                try {
                    $pinger = New-Object System.Net.NetworkInformation.Ping
                    $reply = $pinger.Send($ip, 1000)
                    $results[$ip] = ($reply.Status -eq 'Success')
                    $pinger.Dispose()
                } catch {
                    $results[$ip] = $false
                }
            }

            if (-not $SyncHash.WatchdogCancel) {
                $SyncHash.WatchdogResults = $results
                $SyncHash.WatchdogUpdated = $true
            }

            # Wait for the interval, checking cancel every 500ms
            $waited = 0
            while ($waited -lt $IntervalMs -and -not $SyncHash.WatchdogCancel) {
                [System.Threading.Thread]::Sleep(500)
                $waited += 500
            }
        }
    }).AddArgument($ipList).AddArgument($sync).AddArgument(3000) | Out-Null

    $watchdogPS.BeginInvoke() | Out-Null
    $script:watchdogRunspace = @{ PS = $watchdogPS; RS = $watchdogRS }
})

# -- Identify Selected --
$btnIdentify.Add_Click({
    if (-not $plinkPath) {
        [System.Windows.Forms.MessageBox]::Show("plink.exe not found. Please install PuTTY.", "Error")
        return
    }
    if ($script:credentials.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No credentials configured. Go to the Credentials tab and add at least one.", "Error")
        return
    }

    $selectedIPs = @()
    foreach ($row in $dgvScan.Rows) {
        if ($row.Cells["Selected"].Value -eq $true) {
            $selectedIPs += $row.Cells["IP"].Value
        }
    }
    if ($selectedIPs.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No devices selected.", "Info")
        return
    }

    $sync.Cancel = $false
    $sync.IdentifyResults = @()
    $sync.IdentifyStatus = "Identifying devices..."
    $sync.IdentifyComplete = $false
    $btnIdentify.Enabled = $false
    $btnScan.Enabled = $false
    $btnScanStop.Enabled = $true

    # Update status to "Identifying..." for selected rows
    foreach ($row in $dgvScan.Rows) {
        if ($row.Cells["Selected"].Value -eq $true) {
            $row.Cells["Status"].Value = "Identifying..."
        }
    }

    $credsArray = @($script:credentials | ForEach-Object { @{ Username = $_.Username; Password = $_.Password; EnablePassword = $_.EnablePassword } })
    $connMethod = $script:connectionMethod
    $vendorOvr = $script:vendorOverride
    $serialCfg = @{}

    $identifyRS = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace($script:sharedISS)
    $identifyRS.Open()

    $identifyPS = [PowerShell]::Create()
    $identifyPS.Runspace = $identifyRS

    $identifyPS.AddScript({
        param($IPs, $PlinkPath, $Creds, $SyncHash, $ConnMethod, $SerialSettings, $VendorOverride)

        # Shared functions injected via InitialSessionState

        $results = @()
        $count = 0
        foreach ($ip in $IPs) {
            if ($SyncHash.Cancel) { break }

            $count++
            $SyncHash.IdentifyStatus = "Identifying $ip ($count of $($IPs.Count))..."

            $deviceResult = @{
                IP       = $ip
                Port     = if ($ConnMethod -eq "Telnet") { "Telnet(23)" } else { "SSH(22)" }
                Type     = "Unknown"
                Hostname = ""
                Model    = ""
                Status   = "Identify Failed"
                Username = ""
                Password = ""
                EnablePassword = ""
                ConnectionMethod = $ConnMethod
            }

            try {
                # Get host key (SSH only)
                $hostKey = Get-PlinkHostKey -PlinkPath $PlinkPath -IP $ip -Method $ConnMethod

                # Try each credential
                foreach ($cred in $Creds) {
                    if ($SyncHash.Cancel) { break }

                    $resp = Invoke-PlinkCommand -PlinkPath $PlinkPath -IP $ip -Username $cred.Username -Password $cred.Password -HostKey $hostKey -Commands @("exit") -Method $ConnMethod -SerialSettings $SerialSettings

                    $combined = "$($resp.StdOut)`n$($resp.StdErr)"

                    # Auth failure check
                    if ($combined -match 'Access denied' -or $combined -match 'FATAL ERROR.*password' -or
                        $combined -match 'Unable to authenticate') {
                        continue
                    }

                    # If vendor is forced (not Auto-Detect), accept first successful auth and assign that type
                    if ($VendorOverride -ne "Auto-Detect") {
                        # We got past auth failure checks, so credentials work
                        if ($resp.ExitCode -eq 0 -or ($combined.Length -gt 10 -and $combined -notmatch 'FATAL ERROR')) {
                            $deviceResult.Type = $VendorOverride
                            $deviceResult.Username = $cred.Username
                            $deviceResult.Password = $cred.Password
                            $deviceResult.EnablePassword = $cred.EnablePassword
                            $deviceResult.Status = "Identified (Manual: $VendorOverride)"

                            # Still try to extract hostname/model from banner
                            if ($VendorOverride -eq "Hirschmann") {
                                if ($combined -match '(\S+)\s+Release\s+(HiOS\S+|HiLCOS\S+|\S+)') {
                                    $deviceResult.Model = "$($Matches[1]) $($Matches[2])"
                                }
                                if ($combined -match 'System Name\s*:\s*(.+)') {
                                    $deviceResult.Hostname = $Matches[1].Trim()
                                }
                            } elseif ($VendorOverride -eq "Cisco") {
                                if ($combined -match '(\S+)[#>]\s*$') {
                                    $deviceResult.Hostname = $Matches[1].Trim()
                                }
                                # Probe with 'show version' for model info
                                $probeCmds = @("terminal length 0", "show version", "exit")
                                if ($cred.EnablePassword) {
                                    $probeCmds = @("enable", $cred.EnablePassword, "terminal length 0", "show version", "exit")
                                }
                                $probeResp = Invoke-PlinkInteractive -PlinkPath $PlinkPath -IP $ip `
                                    -Username $cred.Username -Password $cred.Password -HostKey $hostKey `
                                    -Commands $probeCmds -Timeout 20000 -ReadDelay 4000 -Method $ConnMethod -SerialSettings $SerialSettings
                                $probeOut = "$($probeResp.StdOut)`n$($probeResp.StdErr)"
                                if ($probeOut -match '(\S+)[#>]\s' -and -not $deviceResult.Hostname) {
                                    $deviceResult.Hostname = $Matches[1].Trim()
                                }
                                if ($probeOut -match 'Model\s+[Nn]umber\s*:\s*(\S+)') {
                                    $deviceResult.Model = $Matches[1].Trim()
                                } elseif ($probeOut -match 'cisco\s+(IE-\S+|IE\S+|C\S+|WS-\S+|N\S+)\s') {
                                    $deviceResult.Model = $Matches[1].Trim()
                                } elseif ($probeOut -match '(\S+)\s+processor.*with\s+\d+') {
                                    $deviceResult.Model = $Matches[1].Trim()
                                }
                                if ($probeOut -match 'Version\s+(\d+\.\d+\S*)') {
                                    $deviceResult.Model = "$($deviceResult.Model) IOS $($Matches[1].Trim())".Trim()
                                }
                            }
                            break
                        }
                        continue
                    }

                    # Hirschmann detection (Auto-Detect mode)
                    if ($combined -match 'Hirschmann' -or $combined -match 'HiOS' -or $combined -match 'HiLCOS') {
                        $deviceResult.Type = "Hirschmann"
                        $deviceResult.Username = $cred.Username
                        $deviceResult.Password = $cred.Password
                        $deviceResult.EnablePassword = $cred.EnablePassword
                        $deviceResult.Status = "Identified"

                        if ($combined -match '(\S+)\s+Release\s+(HiOS\S+|HiLCOS\S+|\S+)') {
                            $deviceResult.Model = "$($Matches[1]) $($Matches[2])"
                        }
                        if ($combined -match 'System Name\s*:\s*(.+)') {
                            $deviceResult.Hostname = $Matches[1].Trim()
                        }
                        break
                    }

                    # Cisco detection (Auto-Detect mode)
                    if ($combined -match 'Cisco' -or $combined -match 'IOS') {
                        $deviceResult.Type = "Cisco"
                        $deviceResult.Username = $cred.Username
                        $deviceResult.Password = $cred.Password
                        $deviceResult.EnablePassword = $cred.EnablePassword
                        $deviceResult.Status = "Identified"

                        if ($combined -match '(\S+)[#>]\s*$') {
                            $deviceResult.Hostname = $Matches[1].Trim()
                        }
                        # Probe with 'show version' for model info
                        $probeCmds = @("terminal length 0", "show version", "exit")
                        if ($cred.EnablePassword) {
                            $probeCmds = @("enable", $cred.EnablePassword, "terminal length 0", "show version", "exit")
                        }
                        $probeResp = Invoke-PlinkInteractive -PlinkPath $PlinkPath -IP $ip `
                            -Username $cred.Username -Password $cred.Password -HostKey $hostKey `
                            -Commands $probeCmds -Timeout 20000 -ReadDelay 4000 -Method $ConnMethod -SerialSettings $SerialSettings
                        $probeOut = "$($probeResp.StdOut)`n$($probeResp.StdErr)"
                        if ($probeOut -match 'Model\s+[Nn]umber\s*:\s*(\S+)') {
                            $deviceResult.Model = $Matches[1].Trim()
                        } elseif ($probeOut -match 'cisco\s+(IE-\S+|IE\S+|C\S+|WS-\S+|N\S+)\s') {
                            $deviceResult.Model = $Matches[1].Trim()
                        } elseif ($probeOut -match '(\S+)\s+processor.*with\s+\d+') {
                            $deviceResult.Model = $Matches[1].Trim()
                        }
                        if ($probeOut -match 'Version\s+(\d+\.\d+\S*)') {
                            $deviceResult.Model = "$($deviceResult.Model) IOS $($Matches[1].Trim())".Trim()
                        }
                        break
                    }

                    # If we got a response without errors, probe with 'show version' to identify the device
                    if ($resp.ExitCode -eq 0 -or ($combined.Length -gt 10 -and $combined -notmatch 'FATAL ERROR')) {
                        $deviceResult.Username = $cred.Username
                        $deviceResult.Password = $cred.Password
                        $deviceResult.EnablePassword = $cred.EnablePassword

                        # Probe: run 'show version' interactively to identify vendor/model
                        $probeCmds = @("terminal length 0", "show version", "exit")
                        if ($cred.EnablePassword) {
                            $probeCmds = @("enable", $cred.EnablePassword, "terminal length 0", "show version", "exit")
                        }
                        $probeResp = Invoke-PlinkInteractive -PlinkPath $PlinkPath -IP $ip `
                            -Username $cred.Username -Password $cred.Password -HostKey $hostKey `
                            -Commands $probeCmds -Timeout 20000 -ReadDelay 4000 -Method $ConnMethod -SerialSettings $SerialSettings
                        $probeOut = "$($probeResp.StdOut)`n$($probeResp.StdErr)"

                        if ($probeOut -match 'Cisco' -or $probeOut -match 'IOS') {
                            $deviceResult.Type = "Cisco"
                            $deviceResult.Status = "Identified"
                            # Extract hostname from prompt
                            if ($probeOut -match '(\S+)[#>]\s') {
                                $deviceResult.Hostname = $Matches[1].Trim()
                            }
                            # Extract model from 'show version' output
                            if ($probeOut -match 'Model\s+[Nn]umber\s*:\s*(\S+)') {
                                $deviceResult.Model = $Matches[1].Trim()
                            } elseif ($probeOut -match 'cisco\s+(IE-\S+|IE\S+|C\S+|WS-\S+|N\S+)\s') {
                                $deviceResult.Model = $Matches[1].Trim()
                            } elseif ($probeOut -match '(\S+)\s+processor.*with\s+\d+') {
                                $deviceResult.Model = $Matches[1].Trim()
                            }
                            # Extract firmware version
                            if ($probeOut -match 'Version\s+(\d+\.\d+\S*)') {
                                $deviceResult.Model = "$($deviceResult.Model) IOS $($Matches[1].Trim())".Trim()
                            }
                            break
                        }

                        # Still unknown after probe
                        $deviceResult.Status = "Auth OK, Unknown Type"
                        break
                    }
                }
            } catch {
                $deviceResult.Status = "Error: $($_.Exception.Message)"
            }

            $results += $deviceResult
        }

        $SyncHash.IdentifyResults = $results
        $SyncHash.IdentifyComplete = $true
    }).AddArgument($selectedIPs).AddArgument($plinkPath).AddArgument($credsArray).AddArgument($sync).AddArgument($connMethod).AddArgument($serialCfg).AddArgument($vendorOvr) | Out-Null

    $identifyPS.BeginInvoke() | Out-Null
    $script:activeRunspace = @{ PS = $identifyPS; RS = $identifyRS }
})

# -- Credential Add --
$btnAddCred.Add_Click({
    $user = $txtUsername.Text.Trim()
    $pass = $txtPassword.Text
    $enable = $txtEnablePass.Text
    if (-not $user) {
        [System.Windows.Forms.MessageBox]::Show("Username is required.", "Input Required")
        return
    }
    $script:credentials.Add(@{
        Username       = $user
        Password       = $pass
        EnablePassword = $enable
    }) | Out-Null

    if ($script:showPasswords) {
        $displayPass = $pass
        $displayEnable = $enable
    } else {
        $displayPass = if ($pass.Length -gt 0) { "*" * [Math]::Min($pass.Length, 8) } else { "" }
        $displayEnable = if ($enable.Length -gt 0) { "*" * [Math]::Min($enable.Length, 8) } else { "" }
    }
    $dgvCreds.Rows.Add($user, $displayPass, $displayEnable) | Out-Null

    $txtUsername.Text = ""
    $txtPassword.Text = ""
    $txtEnablePass.Text = ""
    $txtUsername.Focus()

    # Auto-save credentials
    try { Export-EncryptedCredentials -Credentials $script:credentials -FilePath $script:credFilePath } catch {}
})

# -- Credential Remove --
$btnRemoveCred.Add_Click({
    if ($dgvCreds.SelectedRows.Count -eq 0) { return }
    $indices = @($dgvCreds.SelectedRows | ForEach-Object { $_.Index }) | Sort-Object -Descending
    foreach ($idx in $indices) {
        $script:credentials.RemoveAt($idx)
        $dgvCreds.Rows.RemoveAt($idx)
    }

    # Auto-save credentials
    try { Export-EncryptedCredentials -Credentials $script:credentials -FilePath $script:credFilePath } catch {}
})

# -- Save Credentials --
$btnSaveCreds.Add_Click({
    if ($script:credentials.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No credentials to save.", "Info")
        return
    }
    $outDir = $txtOutputDir.Text.Trim()
    if (-not $outDir -or -not (Test-Path $outDir)) {
        $outDir = [Environment]::GetFolderPath('Desktop')
    }
    $filePath = Join-Path $outDir "switch_creds.xml"
    try {
        Export-EncryptedCredentials -Credentials $script:credentials -FilePath $filePath
        [System.Windows.Forms.MessageBox]::Show("Credentials saved to:`n$filePath", "Saved")
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Error saving credentials: $($_.Exception.Message)", "Error")
    }
})

# -- Load Credentials --
$btnLoadCreds.Add_Click({
    $outDir = $txtOutputDir.Text.Trim()
    if (-not $outDir -or -not (Test-Path $outDir)) {
        $outDir = [Environment]::GetFolderPath('Desktop')
    }
    $filePath = Join-Path $outDir "switch_creds.xml"
    if (-not (Test-Path $filePath)) {
        [System.Windows.Forms.MessageBox]::Show("No saved credentials found at:`n$filePath", "Not Found")
        return
    }
    try {
        $loaded = Import-EncryptedCredentials -FilePath $filePath
        if ($loaded.Count -eq 0) {
            [System.Windows.Forms.MessageBox]::Show("Could not decrypt credentials (wrong user/machine?).", "Error")
            return
        }
        $script:credentials.Clear()
        $dgvCreds.Rows.Clear()
        foreach ($cred in $loaded) {
            $script:credentials.Add($cred) | Out-Null
            if ($script:showPasswords) {
                $displayPass = $cred.Password
                $displayEnable = $cred.EnablePassword
            } else {
                $displayPass = if ($cred.Password.Length -gt 0) { "*" * [Math]::Min($cred.Password.Length, 8) } else { "" }
                $displayEnable = if ($cred.EnablePassword.Length -gt 0) { "*" * [Math]::Min($cred.EnablePassword.Length, 8) } else { "" }
            }
            $dgvCreds.Rows.Add($cred.Username, $displayPass, $displayEnable) | Out-Null
        }
        [System.Windows.Forms.MessageBox]::Show("Loaded $($loaded.Count) credential(s).", "Loaded")
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Error loading credentials: $($_.Exception.Message)", "Error")
    }
})

# -- Browse output directory --
$btnBrowse.Add_Click({
    $fbd = New-Object System.Windows.Forms.FolderBrowserDialog
    $fbd.Description = "Select output directory for config backups"
    $fbd.SelectedPath = $txtOutputDir.Text
    if ($fbd.ShowDialog() -eq 'OK') {
        $txtOutputDir.Text = $fbd.SelectedPath
    }
})

# -- Open Folder button --
$btnOpenFolder.Add_Click({
    $dir = $txtOutputDir.Text.Trim()
    if ($dir -and (Test-Path $dir)) {
        Start-Process explorer.exe $dir
    } else {
        [System.Windows.Forms.MessageBox]::Show("Directory does not exist:`n$dir", "Folder Not Found")
    }
})

# -- Backup function (shared by Backup Selected and Backup All) --
function Start-Backup {
    param([array]$DevicesToBackup)

    if (-not $plinkPath) {
        [System.Windows.Forms.MessageBox]::Show("plink.exe not found. Please install PuTTY.", "Error")
        return
    }
    if ($script:credentials.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No credentials configured.", "Error")
        return
    }
    $outDir = $txtOutputDir.Text.Trim()
    if (-not $outDir -or -not (Test-Path $outDir)) {
        [System.Windows.Forms.MessageBox]::Show("Please select a valid output directory.", "Error")
        return
    }
    if ($DevicesToBackup.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No identified devices to back up.", "Info")
        return
    }

    $sync.Cancel = $false
    $sync.BackupResults = @()
    $sync.BackupStatus = ""
    $sync.BackupComplete = $false
    $sync.BackupLog = @()
    $sync.LogIndex = 0
    $rtbLog.Clear()
    $dgvBackup.Rows.Clear()
    $progressBackup.Value = 0

    # Initialize backup results
    $initResults = @()
    foreach ($dev in $DevicesToBackup) {
        $initResults += @{
            IP       = $dev.IP
            Type     = $dev.Type
            Hostname = $dev.Hostname
            Status   = "Pending"
            Filename = ""
        }
    }
    $sync.BackupResults = $initResults
    $sync.BackupStatus = "Starting backup..."

    $btnBackupSelected.Enabled = $false
    $btnBackupAll.Enabled = $false
    $btnBackupStop.Enabled = $true

    # Prepare device data and credentials for the background runspace
    $devArray = @($DevicesToBackup | ForEach-Object {
        @{
            IP       = $_.IP
            Type     = $_.Type
            Hostname = $_.Hostname
            Model    = $_.Model
            Username = $_.Username
            Password = $_.Password
            EnablePassword = $_.EnablePassword
        }
    })
    $credsArray = @($script:credentials | ForEach-Object {
        @{ Username = $_.Username; Password = $_.Password; EnablePassword = $_.EnablePassword }
    })
    $connMethod = $script:connectionMethod
    $vendorOvr = $script:vendorOverride
    $serialCfg = @{}

    $backupRS = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace($script:sharedISS)
    $backupRS.Open()

    $backupPS = [PowerShell]::Create()
    $backupPS.Runspace = $backupRS

    $backupPS.AddScript({
        param($Devices, $Creds, $PlinkPath, $OutputDir, $SyncHash, $ConnMethod, $SerialSettings, $VendorOverride)

        Add-SyncLog -SyncHash $SyncHash -Channel "Backup" -Message "Backup started for $($Devices.Count) device(s)."
        $count = 0

        foreach ($dev in $Devices) {
            if ($SyncHash.Cancel) {
                Add-SyncLog -SyncHash $SyncHash -Channel "Backup" -Message "Backup cancelled by user."
                break
            }

            $count++
            $ip = $dev.IP
            $type = $dev.Type
            $hostname = $dev.Hostname
            $username = $dev.Username
            $password = $dev.Password
            $enablePass = $dev.EnablePassword

            Add-SyncLog -SyncHash $SyncHash -Channel "Backup" -Message "[$count/$($Devices.Count)] Processing $ip ($type) - $hostname"

            # Update status in results
            $results = $SyncHash.BackupResults
            for ($i = 0; $i -lt $results.Count; $i++) {
                if ($results[$i].IP -eq $ip) {
                    $results[$i].Status = "In Progress..."
                    break
                }
            }
            $SyncHash.BackupResults = $results
            $SyncHash.BackupStatus = "Backing up $ip..."

            try {
                # Get host key (SSH only)
                $hostKey = $null
                if ($ConnMethod -eq "SSH") {
                    Add-SyncLog -SyncHash $SyncHash -Channel "Backup" -Message "  Getting host key for $ip..."
                    $hostKey = Get-PlinkHostKey -PlinkPath $PlinkPath -IP $ip -Method $ConnMethod

                    if (-not $hostKey) {
                        Add-SyncLog -SyncHash $SyncHash -Channel "Backup" -Message "[ERROR] Could not get host key for $ip"
                        for ($i = 0; $i -lt $results.Count; $i++) {
                            if ($results[$i].IP -eq $ip) {
                                $results[$i].Status = "Failed: No host key"
                                break
                            }
                        }
                        $SyncHash.BackupResults = $results
                        continue
                    }
                }

                # If no credentials stored on the device object, try cycling through all creds
                if (-not $username) {
                    Add-SyncLog -SyncHash $SyncHash -Channel "Backup" -Message "  No stored credentials, trying all..."
                    foreach ($cred in $Creds) {
                        $username = $cred.Username
                        $password = $cred.Password
                        $enablePass = $cred.EnablePassword
                        # Quick auth test
                        $testPsi = New-Object System.Diagnostics.ProcessStartInfo
                        $testPsi.FileName = $PlinkPath
                        if ($ConnMethod -eq "Serial" -or $ConnMethod -eq "Telnet") {
                            # Serial/Telnet: use interactive mode (no -batch) with delays
                            $testArgs = Build-PlinkArgs -Method $ConnMethod -IP $ip -Username $username `
                                -Password $password -HostKey $hostKey -SerialSettings $SerialSettings
                        } else {
                            $testArgs = Build-PlinkArgs -Method $ConnMethod -IP $ip -Username $username `
                                -Password $password -HostKey $hostKey -SerialSettings $SerialSettings -BatchMode
                        }
                        $testPsi.Arguments = $testArgs
                        $testPsi.UseShellExecute = $false
                        $testPsi.RedirectStandardOutput = $true
                        $testPsi.RedirectStandardError = $true
                        $testPsi.RedirectStandardInput = $true
                        $testPsi.CreateNoWindow = $true
                        $testProc = [System.Diagnostics.Process]::Start($testPsi)

                        # Start async reads immediately before any stdin writes
                        $testOut = $testProc.StandardOutput.ReadToEndAsync()
                        $testErr = $testProc.StandardError.ReadToEndAsync()

                        if ($ConnMethod -eq "Telnet") {
                            Start-Sleep -Milliseconds 1000
                            $testProc.StandardInput.WriteLine($username)
                            Start-Sleep -Milliseconds 500
                            $testProc.StandardInput.WriteLine($password)
                            Start-Sleep -Milliseconds 1000
                        } elseif ($ConnMethod -eq "Serial") {
                            # Serial console: no login needed, just wait for prompt
                            Start-Sleep -Milliseconds 1000
                        }
                        $testProc.StandardInput.WriteLine("exit")
                        Start-Sleep -Milliseconds 1000
                        $testProc.StandardInput.Close()
                        $testTimeout = if ($ConnMethod -eq "Serial") { 15000 } else { 10000 }
                        if (-not $testProc.WaitForExit($testTimeout)) {
                            try { $testProc.Kill() } catch {}
                        }
                        $outStr = ""; $errStr = ""
                        try { if ($testOut.Wait(3000)) { $outStr = $testOut.Result } } catch {}
                        try { if ($testErr.Wait(3000)) { $errStr = $testErr.Result } } catch {}
                        # Ensure process is fully dead and handle released (critical for serial port)
                        try { if (-not $testProc.HasExited) { $testProc.Kill() } } catch {}
                        try { $testProc.Dispose() } catch {}
                        $combined = "$outStr`n$errStr"
                        if ($combined -notmatch 'Access denied' -and $combined -notmatch 'FATAL ERROR.*password') {
                            Add-SyncLog -SyncHash $SyncHash -Channel "Backup" -Message "  Authenticated with $username"
                            # Wait for OS to release COM port before next plink session
                            if ($ConnMethod -eq "Serial") { Start-Sleep -Milliseconds 1500 }
                            break
                        }
                        # Wait between retries so COM port is freed
                        if ($ConnMethod -eq "Serial") { Start-Sleep -Milliseconds 1000 }
                        $username = $null
                    }
                    if (-not $username) {
                        Add-SyncLog -SyncHash $SyncHash -Channel "Backup" -Message "[ERROR] Auth failed for all credentials on $ip"
                        for ($i = 0; $i -lt $results.Count; $i++) {
                            if ($results[$i].IP -eq $ip) {
                                $results[$i].Status = "Failed: Auth"
                                break
                            }
                        }
                        $SyncHash.BackupResults = $results
                        continue
                    }
                }

                # Download config based on type
                # If type is unknown but vendor override is set, use the override
                $effectiveType = $type
                if (($effectiveType -eq "Unknown" -or $effectiveType -eq "") -and $VendorOverride -ne "Auto-Detect") {
                    $effectiveType = $VendorOverride
                    Add-SyncLog -SyncHash $SyncHash -Channel "Backup" -Message "  Using vendor override: $VendorOverride for $ip"
                }

                $rawOutput = ""
                $cleanedConfig = ""

                if ($effectiveType -eq "Hirschmann") {
                    Add-SyncLog -SyncHash $SyncHash -Channel "Backup" -Message "  Downloading Hirschmann config from $ip..."
                    $spaces = " " * 200
                    $commands = @("show running-config script", $spaces, $spaces, $spaces, $spaces, $spaces, "exit")
                    $resp = Invoke-PlinkInteractive -PlinkPath $PlinkPath -IP $ip -Username $username -Password $password -HostKey $hostKey -Commands $commands -Timeout 60000 -ReadDelay 8000 -Method $ConnMethod -SerialSettings $SerialSettings
                    $rawOutput = $resp.StdOut
                    $cleanedConfig = Clean-HirschmannOutput -RawOutput $rawOutput

                } elseif ($effectiveType -eq "Cisco") {
                    Add-SyncLog -SyncHash $SyncHash -Channel "Backup" -Message "  Downloading Cisco config from $ip..."
                    $commands = @("enable", $enablePass, "terminal length 0", "show running-config", "exit")
                    $resp = Invoke-PlinkInteractive -PlinkPath $PlinkPath -IP $ip -Username $username -Password $password -HostKey $hostKey -Commands $commands -Timeout 60000 -ReadDelay 8000 -Method $ConnMethod -SerialSettings $SerialSettings
                    $rawOutput = $resp.StdOut
                    $cleanedConfig = Clean-CiscoOutput -RawOutput $rawOutput

                } else {
                    Add-SyncLog -SyncHash $SyncHash -Channel "Backup" -Message "  Unknown device type for $ip, attempting generic config download..."
                    $commands = @("show running-config", "exit")
                    $resp = Invoke-PlinkInteractive -PlinkPath $PlinkPath -IP $ip -Username $username -Password $password -HostKey $hostKey -Commands $commands -Timeout 30000 -ReadDelay 5000 -Method $ConnMethod -SerialSettings $SerialSettings
                    $rawOutput = $resp.StdOut
                    $cleanedConfig = $rawOutput
                }

                # Check stderr for errors (ignore benign SSH channel close errors if we got output)
                $isFatalErr = $resp.StdErr -match 'FATAL ERROR' -or $resp.StdErr -match 'Access denied'
                $isBenignEOF = $resp.StdErr -match 'SSH2_MSG_CHANNEL_EOF' -and $resp.StdOut.Length -gt 50
                if ($isFatalErr -and -not $isBenignEOF) {
                    Add-SyncLog -SyncHash $SyncHash -Channel "Backup" -Message "[ERROR] Connection error for $ip : $($resp.StdErr.Trim())"
                    for ($i = 0; $i -lt $results.Count; $i++) {
                        if ($results[$i].IP -eq $ip) {
                            $results[$i].Status = "Failed: Connection Error"
                            break
                        }
                    }
                    $SyncHash.BackupResults = $results
                    continue
                }

                # Determine filename
                $ts = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
                $safeName = Sanitize-Filename -Name $hostname
                $fileName = "${safeName}_${ip}_${ts}.txt"

                # Save config
                $parseError = $false
                if ($cleanedConfig.Length -lt 20) {
                    # Config too short - likely a parse error, save raw
                    $parseError = $true
                    $fileName = "${safeName}_${ip}_${ts}_raw.txt"
                    $filePath = Join-Path $OutputDir $fileName
                    [System.IO.File]::WriteAllText($filePath, $rawOutput, [System.Text.Encoding]::UTF8)
                    Add-SyncLog -SyncHash $SyncHash -Channel "Backup" -Message "[ERROR] Parse error for $ip - raw output saved to $fileName"
                } else {
                    $filePath = Join-Path $OutputDir $fileName
                    [System.IO.File]::WriteAllText($filePath, $cleanedConfig, [System.Text.Encoding]::UTF8)
                    Add-SyncLog -SyncHash $SyncHash -Channel "Backup" -Message "  Config saved: $fileName ($($cleanedConfig.Length) bytes)"
                }

                for ($i = 0; $i -lt $results.Count; $i++) {
                    if ($results[$i].IP -eq $ip) {
                        $results[$i].Status = if ($parseError) { "Parse Error" } else { "Success" }
                        $results[$i].Filename = $fileName
                        break
                    }
                }
                $SyncHash.BackupResults = $results

            } catch {
                Add-SyncLog -SyncHash $SyncHash -Channel "Backup" -Message "[ERROR] Exception for $ip : $($_.Exception.Message)"
                $results = $SyncHash.BackupResults
                for ($i = 0; $i -lt $results.Count; $i++) {
                    if ($results[$i].IP -eq $ip) {
                        $results[$i].Status = "Failed: Exception"
                        break
                    }
                }
                $SyncHash.BackupResults = $results
            }
        }

        Add-SyncLog -SyncHash $SyncHash -Channel "Backup" -Message "Backup process complete."
        $SyncHash.BackupComplete = $true
    }).AddArgument($devArray).AddArgument($credsArray).AddArgument($plinkPath).AddArgument($outDir).AddArgument($sync).AddArgument($connMethod).AddArgument($serialCfg).AddArgument($vendorOvr) | Out-Null

    $backupPS.BeginInvoke() | Out-Null
    $script:activeRunspace = @{ PS = $backupPS; RS = $backupRS }
}

# -- Backup Selected button --
$btnBackupSelected.Add_Click({
    # Get devices that are selected in the scan grid and have been identified
    $devicesToBackup = @()
    foreach ($row in $dgvScan.Rows) {
        if ($row.Cells["Selected"].Value -eq $true) {
            $ip = $row.Cells["IP"].Value
            # Find matching device data
            foreach ($dev in $script:devices) {
                if ($dev.IP -eq $ip) {
                    $devicesToBackup += $dev
                    break
                }
            }
        }
    }
    Start-Backup -DevicesToBackup $devicesToBackup
})

# -- Backup All button --
$btnBackupAll.Add_Click({
    $devicesToBackup = @($script:devices | Where-Object { $_.Port -ne "" })
    Start-Backup -DevicesToBackup $devicesToBackup
})

# -- Backup Stop button --
$btnBackupStop.Add_Click({
    $sync.Cancel = $true
    $btnBackupStop.Enabled = $false
})

# ---------------------------------------------------------------------------
# Audit Tab: Built-in Command Lists
# ---------------------------------------------------------------------------
$script:ciscoShowCommands = @(
    "show running-config",
    "show startup-config",
    "show version",
    "show inventory",
    "show interfaces",
    "show interfaces status",
    "show interfaces trunk",
    "show ip interface brief",
    "show ip route",
    "show ip arp",
    "show mac address-table",
    "show vlan brief",
    "show vlan",
    "show spanning-tree",
    "show spanning-tree summary",
    "show cdp neighbors",
    "show cdp neighbors detail",
    "show lldp neighbors",
    "show lldp neighbors detail",
    "show etherchannel summary",
    "show port-channel summary",
    "show logging",
    "show clock",
    "show ntp status",
    "show ntp associations",
    "show snmp",
    "show snmp community",
    "show access-lists",
    "show ip access-lists",
    "show environment",
    "show power inline",
    "show processes cpu",
    "show memory statistics",
    "show flash:",
    "show boot",
    "show users",
    "show privilege",
    "show aaa servers",
    "show ip dhcp snooping",
    "show ip dhcp snooping binding",
    "show storm-control",
    "show errdisable recovery",
    "show platform",
    "show switch",
    "show switch stack-ports"
)

$script:hirschmannShowCommands = @(
    # --- System & Device Info ---
    "show running-config",
    "show system info",
    "show device-status",
    "show system resources",
    "show system temperature limits",
    "show system temperature extremes",
    "show system flash-status",
    "show network parms",
    "show users",
    "show signal-contact",
    # --- Interfaces & Ports ---
    "show port",
    "show interface counters",
    "show interface statistics",
    "show interface utilization",
    "show interfaces switchport",
    # --- VLANs ---
    "show vlan",
    "show vlan brief",
    "show vlan port",
    "show vlan member current",
    "show vlan member static",
    # --- Spanning Tree ---
    "show spanning-tree global",
    "show spanning-tree port",
    "show spanning-tree mst instance",
    "show spanning-tree mst port",
    "show spanning-tree mst vlan",
    # --- MAC / Forwarding ---
    "show mac-addr-table",
    "show mac-filter-table",
    "show mac-filter-table igmpsnooping",
    "show mac-filter-table stats",
    # --- LLDP ---
    "show lldp global",
    "show lldp port",
    "show lldp remote-data all",
    "show lldp remote-data all detailed",
    # --- IP / ARP ---
    "show ip interface",
    "show ip global",
    "show ip arp table",
    "show ip arp-inspection global",
    "show address-conflict detected",
    # --- Logging ---
    "show logging buffered",
    "show logging host",
    "show logging traplogs",
    "show logging persistent",
    "show logging syslog",
    # --- SNMP ---
    "show snmp community",
    "show snmp traps",
    "show snmp access",
    # --- Time (SNTP / NTP) ---
    "show sntp global",
    "show sntp client status",
    "show sntp client server",
    "show ntp client-status",
    "show ntp server-status",
    # --- Ring Redundancy ---
    "show hiper-ring global",
    "show mrp",
    # --- Link Aggregation / LACP ---
    "show link-aggregation global",
    "show link-aggregation port",
    "show link-aggregation statistics",
    "show lacp interface",
    "show lacp actor",
    # --- Multicast / IGMP ---
    "show igmp-snooping global",
    "show igmp-snooping interface all",
    "show igmp-snooping vlan all",
    "show igmp-snooping statistics global",
    "show igmp-snooping querier global",
    "show igmp-snooping querier vlan all",
    # --- QoS / Classification ---
    "show classofservice dot1p-mapping",
    "show classofservice ip-dscp-mapping",
    "show classofservice trust",
    "show cos-queue",
    # --- Packet Filtering / ACLs ---
    "show packet-filter l3 global",
    "show packet-filter l3 ruletable",
    # --- Power over Ethernet ---
    "show inlinepower global",
    "show inlinepower port"
)

# Keep a copy of the built-in defaults so Reset Defaults can restore them
$script:ciscoShowCommandsDefault = @($script:ciscoShowCommands)
$script:hirschmannShowCommandsDefault = @($script:hirschmannShowCommands)

# Load user-saved command lists (overrides built-in defaults if files exist)
$loadedCisco = Load-CommandList -FilePath $script:ciscoCmdsFilePath
if ($loadedCisco) { $script:ciscoShowCommands = $loadedCisco }

$loadedHirschmann = Load-CommandList -FilePath $script:hirschmannCmdsFilePath
if ($loadedHirschmann) { $script:hirschmannShowCommands = $loadedHirschmann }

# ---------------------------------------------------------------------------
# Audit Tab: Command List Picker Dialog
# ---------------------------------------------------------------------------
function Show-CommandPicker {
    param(
        [string]$Title,
        [string[]]$CommandList,
        [System.Windows.Forms.TextBox]$TargetTextBox,
        [string]$VendorKey
    )
    # Resolve the defaults and file path for this vendor
    $defaultList = @()
    $saveFilePath = $null
    if ($VendorKey -eq "Cisco") {
        $defaultList = $script:ciscoShowCommandsDefault
        $saveFilePath = $script:ciscoCmdsFilePath
    } elseif ($VendorKey -eq "Hirschmann") {
        $defaultList = $script:hirschmannShowCommandsDefault
        $saveFilePath = $script:hirschmannCmdsFilePath
    }

    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text = $Title
    $dlg.Size = New-Object System.Drawing.Size(600, 600)
    $dlg.StartPosition = "CenterParent"
    $dlg.MinimumSize = New-Object System.Drawing.Size(450, 380)
    $dlg.Font = New-Object System.Drawing.Font("Segoe UI", 9)

    $lblInstr = New-Object System.Windows.Forms.Label
    $lblInstr.Text = "Check commands to add. Double-click to edit. Edits are saved automatically for next time."
    $lblInstr.Dock = 'Top'
    $lblInstr.Height = 24
    $dlg.Controls.Add($lblInstr)

    # -- Bottom button panel --
    $panelDlgBtn = New-Object System.Windows.Forms.Panel
    $panelDlgBtn.Dock = 'Bottom'
    $panelDlgBtn.Height = 42
    $dlg.Controls.Add($panelDlgBtn)

    $btnDlgSelectAll = New-Object System.Windows.Forms.Button
    $btnDlgSelectAll.Text = "Select All"
    $btnDlgSelectAll.Location = New-Object System.Drawing.Point(5, 7)
    $btnDlgSelectAll.Size = New-Object System.Drawing.Size(80, 27)
    $panelDlgBtn.Controls.Add($btnDlgSelectAll)

    $btnDlgSelectNone = New-Object System.Windows.Forms.Button
    $btnDlgSelectNone.Text = "Select None"
    $btnDlgSelectNone.Location = New-Object System.Drawing.Point(90, 7)
    $btnDlgSelectNone.Size = New-Object System.Drawing.Size(85, 27)
    $panelDlgBtn.Controls.Add($btnDlgSelectNone)

    $btnDlgReset = New-Object System.Windows.Forms.Button
    $btnDlgReset.Text = "Reset Defaults"
    $btnDlgReset.Location = New-Object System.Drawing.Point(185, 7)
    $btnDlgReset.Size = New-Object System.Drawing.Size(105, 27)
    $panelDlgBtn.Controls.Add($btnDlgReset)

    $btnDlgOK = New-Object System.Windows.Forms.Button
    $btnDlgOK.Text = "Add Selected"
    $btnDlgOK.Location = New-Object System.Drawing.Point(390, 7)
    $btnDlgOK.Size = New-Object System.Drawing.Size(100, 27)
    $btnDlgOK.Anchor = 'Top,Right'
    $btnDlgOK.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $panelDlgBtn.Controls.Add($btnDlgOK)

    $btnDlgCancel = New-Object System.Windows.Forms.Button
    $btnDlgCancel.Text = "Cancel"
    $btnDlgCancel.Location = New-Object System.Drawing.Point(495, 7)
    $btnDlgCancel.Size = New-Object System.Drawing.Size(80, 27)
    $btnDlgCancel.Anchor = 'Top,Right'
    $btnDlgCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $panelDlgBtn.Controls.Add($btnDlgCancel)

    # -- Middle panel: Add custom command row --
    $panelDlgAdd = New-Object System.Windows.Forms.Panel
    $panelDlgAdd.Dock = 'Bottom'
    $panelDlgAdd.Height = 38
    $dlg.Controls.Add($panelDlgAdd)

    $lblDlgCustom = New-Object System.Windows.Forms.Label
    $lblDlgCustom.Text = "Custom:"
    $lblDlgCustom.Location = New-Object System.Drawing.Point(5, 10)
    $lblDlgCustom.AutoSize = $true
    $panelDlgAdd.Controls.Add($lblDlgCustom)

    $txtDlgCustom = New-Object System.Windows.Forms.TextBox
    $txtDlgCustom.Location = New-Object System.Drawing.Point(60, 7)
    $txtDlgCustom.Size = New-Object System.Drawing.Size(350, 23)
    $txtDlgCustom.Anchor = 'Top,Left,Right'
    $txtDlgCustom.Font = New-Object System.Drawing.Font("Consolas", 9)
    $panelDlgAdd.Controls.Add($txtDlgCustom)

    $btnDlgAdd = New-Object System.Windows.Forms.Button
    $btnDlgAdd.Text = "Add"
    $btnDlgAdd.Location = New-Object System.Drawing.Point(415, 5)
    $btnDlgAdd.Size = New-Object System.Drawing.Size(60, 27)
    $btnDlgAdd.Anchor = 'Top,Right'
    $panelDlgAdd.Controls.Add($btnDlgAdd)

    $btnDlgRemove = New-Object System.Windows.Forms.Button
    $btnDlgRemove.Text = "Remove"
    $btnDlgRemove.Location = New-Object System.Drawing.Point(480, 5)
    $btnDlgRemove.Size = New-Object System.Drawing.Size(70, 27)
    $btnDlgRemove.Anchor = 'Top,Right'
    $panelDlgAdd.Controls.Add($btnDlgRemove)

    # -- DataGridView for editable command list --
    $dgvCmdPick = New-Object System.Windows.Forms.DataGridView
    $dgvCmdPick.Dock = 'Fill'
    $dgvCmdPick.AllowUserToAddRows = $false
    $dgvCmdPick.AllowUserToDeleteRows = $false
    $dgvCmdPick.RowHeadersVisible = $false
    $dgvCmdPick.AutoSizeColumnsMode = 'Fill'
    $dgvCmdPick.SelectionMode = 'FullRowSelect'
    $dgvCmdPick.BackgroundColor = [System.Drawing.SystemColors]::Window
    $dgvCmdPick.Font = New-Object System.Drawing.Font("Consolas", 9)
    $dgvCmdPick.EditMode = 'EditOnF2'

    $colCmdChk = New-Object System.Windows.Forms.DataGridViewCheckBoxColumn
    $colCmdChk.Name = "Selected"
    $colCmdChk.HeaderText = ""
    $colCmdChk.Width = 30
    $colCmdChk.FillWeight = 7
    $dgvCmdPick.Columns.Add($colCmdChk) | Out-Null

    $colCmdText = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
    $colCmdText.Name = "Command"
    $colCmdText.HeaderText = "Command (double-click to edit)"
    $colCmdText.FillWeight = 93
    $dgvCmdPick.Columns.Add($colCmdText) | Out-Null

    # Populate with current command list
    foreach ($cmd in $CommandList) {
        $dgvCmdPick.Rows.Add($false, $cmd) | Out-Null
    }

    $dlg.Controls.Add($dgvCmdPick)
    $dlg.Controls.SetChildIndex($dgvCmdPick, 0)

    $dlg.AcceptButton = $btnDlgOK
    $dlg.CancelButton = $btnDlgCancel

    # -- Toggle checkbox on row click (outside the checkbox cell itself) --
    $dgvCmdPick.Add_CellClick({
        param($s, $e)
        if ($e.RowIndex -ge 0 -and $e.ColumnIndex -ne 0) {
            $current = $dgvCmdPick.Rows[$e.RowIndex].Cells["Selected"].Value
            $dgvCmdPick.Rows[$e.RowIndex].Cells["Selected"].Value = -not $current
        }
    })

    # -- Select All --
    $btnDlgSelectAll.Add_Click({
        foreach ($row in $dgvCmdPick.Rows) { $row.Cells["Selected"].Value = $true }
    })

    # -- Select None --
    $btnDlgSelectNone.Add_Click({
        foreach ($row in $dgvCmdPick.Rows) { $row.Cells["Selected"].Value = $false }
    })

    # -- Reset Defaults: restore the original built-in command list --
    $btnDlgReset.Add_Click({
        $confirm = [System.Windows.Forms.MessageBox]::Show(
            "This will replace the current list with the original built-in commands.`n`nAny custom commands or edits will be lost.`n`nContinue?",
            "Reset to Defaults",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Question
        )
        if ($confirm -eq [System.Windows.Forms.DialogResult]::Yes) {
            $dgvCmdPick.Rows.Clear()
            foreach ($cmd in $defaultList) {
                $dgvCmdPick.Rows.Add($false, $cmd) | Out-Null
            }
        }
    })

    # -- Add custom command --
    $btnDlgAdd.Add_Click({
        $custom = $txtDlgCustom.Text.Trim()
        if ($custom.Length -gt 0) {
            $dgvCmdPick.Rows.Add($true, $custom) | Out-Null
            $txtDlgCustom.Text = ""
            $txtDlgCustom.Focus()
            # Scroll to the new row
            $dgvCmdPick.FirstDisplayedScrollingRowIndex = $dgvCmdPick.Rows.Count - 1
        }
    })

    # -- Allow Enter in the custom textbox to trigger Add --
    $txtDlgCustom.Add_KeyDown({
        param($s, $e)
        if ($e.KeyCode -eq 'Return') {
            $e.SuppressKeyPress = $true
            $btnDlgAdd.PerformClick()
        }
    })

    # -- Remove selected rows --
    $btnDlgRemove.Add_Click({
        $indices = @($dgvCmdPick.SelectedRows | ForEach-Object { $_.Index }) | Sort-Object -Descending
        foreach ($idx in $indices) {
            $dgvCmdPick.Rows.RemoveAt($idx)
        }
    })

    # -- OK: collect checked commands and save the full list --
    if ($dlg.ShowDialog($form) -eq [System.Windows.Forms.DialogResult]::OK) {
        # Commit any pending cell edit before reading values
        $dgvCmdPick.EndEdit()

        # Build the full list of all commands (for saving) and the checked subset (for appending)
        $allCommands = @()
        $selected = @()
        foreach ($row in $dgvCmdPick.Rows) {
            $cmdText = "$($row.Cells['Command'].Value)".Trim()
            if ($cmdText.Length -gt 0) {
                $allCommands += $cmdText
                if ($row.Cells["Selected"].Value -eq $true) {
                    $selected += $cmdText
                }
            }
        }

        # Save the full list back to the script variable and to disk
        if ($VendorKey -eq "Cisco") {
            $script:ciscoShowCommands = $allCommands
        } elseif ($VendorKey -eq "Hirschmann") {
            $script:hirschmannShowCommands = $allCommands
        }
        if ($saveFilePath -and $allCommands.Count -gt 0) {
            Save-CommandList -Commands $allCommands -FilePath $saveFilePath
        }

        # Append checked commands to the audit text box
        if ($selected.Count -gt 0) {
            $existing = $TargetTextBox.Text.TrimEnd("`r", "`n")
            if ($existing.Length -gt 0) {
                $TargetTextBox.Text = $existing + "`r`n" + ($selected -join "`r`n")
            } else {
                $TargetTextBox.Text = ($selected -join "`r`n")
            }
        }
    }
    $dlg.Dispose()
}

# ---------------------------------------------------------------------------
# Audit Tab: Event Handlers
# ---------------------------------------------------------------------------

# -- Audit Browse --
$btnAuditBrowse.Add_Click({
    $fbd = New-Object System.Windows.Forms.FolderBrowserDialog
    $fbd.Description = "Select output directory for audit results"
    $fbd.SelectedPath = $txtAuditDir.Text
    if ($fbd.ShowDialog() -eq 'OK') {
        $txtAuditDir.Text = $fbd.SelectedPath
    }
})

# -- Audit Open Folder --
$btnAuditOpenFolder.Add_Click({
    $dir = $txtAuditDir.Text.Trim()
    if ($dir -and (Test-Path $dir)) {
        Start-Process explorer.exe $dir
    } else {
        [System.Windows.Forms.MessageBox]::Show("Directory does not exist:`n$dir", "Folder Not Found")
    }
})

# -- Cisco Commands button --
$btnAuditCiscoList.Add_Click({
    Show-CommandPicker -Title "Cisco Show Commands" -CommandList $script:ciscoShowCommands -TargetTextBox $txtAuditCmds -VendorKey "Cisco"
})

# -- Hirschmann Commands button --
$btnAuditHirschList.Add_Click({
    Show-CommandPicker -Title "Hirschmann Show Commands" -CommandList $script:hirschmannShowCommands -TargetTextBox $txtAuditCmds -VendorKey "Hirschmann"
})

# -- Clear commands --
$btnAuditClearCmds.Add_Click({
    $txtAuditCmds.Text = ""
})

# -- Audit Stop --
$btnAuditStop.Add_Click({
    $sync.Cancel = $true
    $btnAuditStop.Enabled = $false
})

# -- Audit Run --
$btnAuditRun.Add_Click({
    if (-not $plinkPath) {
        [System.Windows.Forms.MessageBox]::Show("plink.exe not found. Please install PuTTY.", "Error")
        return
    }
    if ($script:credentials.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No credentials configured. Go to the Credentials tab.", "Error")
        return
    }
    $auditDir = $txtAuditDir.Text.Trim()
    if (-not $auditDir -or -not (Test-Path $auditDir)) {
        [System.Windows.Forms.MessageBox]::Show("Please select a valid output directory.", "Error")
        return
    }

    # Parse commands from text box (one per line, skip blanks, cap at 100)
    $rawLines = $txtAuditCmds.Text -split "`r?`n"
    $commands = @($rawLines | ForEach-Object { $_.Trim() } | Where-Object { $_.Length -gt 0 })
    if ($commands.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No commands entered. Use the Cisco/Hirschmann command buttons or type commands manually.", "Info")
        return
    }
    if ($commands.Count -gt 100) {
        [System.Windows.Forms.MessageBox]::Show("Maximum 100 commands allowed. You have $($commands.Count). Please reduce the list.", "Too Many Commands")
        return
    }

    # Get selected devices from scan grid
    $devicesToAudit = @()
    foreach ($row in $dgvScan.Rows) {
        if ($row.Cells["Selected"].Value -eq $true) {
            $ip = $row.Cells["IP"].Value
            foreach ($dev in $script:devices) {
                if ($dev.IP -eq $ip) {
                    $devicesToAudit += $dev
                    break
                }
            }
        }
    }
    if ($devicesToAudit.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No devices selected on the Scan tab. Go to Scan && Discover, select devices, then return here.", "No Devices")
        return
    }

    $sync.Cancel = $false
    $sync.AuditResults = @()
    $sync.AuditStatus = ""
    $sync.AuditComplete = $false
    $sync.AuditLog = @()
    $sync.AuditLogIndex = 0
    $rtbAuditLog.Clear()
    $dgvAudit.Rows.Clear()
    $progressAudit.Value = 0

    # Initialize audit results
    $initResults = @()
    foreach ($dev in $devicesToAudit) {
        $initResults += @{
            IP       = $dev.IP
            Type     = $dev.Type
            Hostname = $dev.Hostname
            Commands = $commands.Count
            Status   = "Pending"
            Filename = ""
        }
    }
    $sync.AuditResults = $initResults
    $sync.AuditStatus = "Starting audit..."

    $btnAuditRun.Enabled = $false
    $btnAuditStop.Enabled = $true

    # Prepare data for background runspace
    $devArray = @($devicesToAudit | ForEach-Object {
        @{
            IP             = $_.IP
            Type           = $_.Type
            Hostname       = $_.Hostname
            Model          = $_.Model
            Username       = $_.Username
            Password       = $_.Password
            EnablePassword = $_.EnablePassword
        }
    })
    $credsArray = @($script:credentials | ForEach-Object {
        @{ Username = $_.Username; Password = $_.Password; EnablePassword = $_.EnablePassword }
    })
    $connMethod = $script:connectionMethod
    $vendorOvr = $script:vendorOverride
    $serialCfg = @{}

    $auditRS = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace($script:sharedISS)
    $auditRS.Open()

    $auditPS = [PowerShell]::Create()
    $auditPS.Runspace = $auditRS

    $auditPS.AddScript({
        param($Devices, $Creds, $PlinkPath, $OutputDir, $SyncHash, $ConnMethod, $SerialSettings, $VendorOverride, $Commands)

        Add-SyncLog -SyncHash $SyncHash -Channel "Audit" -Message "Audit started for $($Devices.Count) device(s) with $($Commands.Count) command(s)."
        $count = 0

        foreach ($dev in $Devices) {
            if ($SyncHash.Cancel) {
                Add-SyncLog -SyncHash $SyncHash -Channel "Audit" -Message "Audit cancelled by user."
                break
            }

            $count++
            $ip = $dev.IP
            $type = $dev.Type
            $hostname = $dev.Hostname
            $username = $dev.Username
            $password = $dev.Password
            $enablePass = $dev.EnablePassword

            # Determine effective type
            $effectiveType = $type
            if (($effectiveType -eq "Unknown" -or $effectiveType -eq "") -and $VendorOverride -ne "Auto-Detect") {
                $effectiveType = $VendorOverride
            }

            Add-SyncLog -SyncHash $SyncHash -Channel "Audit" -Message "[$count/$($Devices.Count)] Auditing $ip ($effectiveType) - $hostname"

            # Update status
            $results = $SyncHash.AuditResults
            for ($i = 0; $i -lt $results.Count; $i++) {
                if ($results[$i].IP -eq $ip) {
                    $results[$i].Status = "In Progress..."
                    break
                }
            }
            $SyncHash.AuditResults = $results
            $SyncHash.AuditStatus = "Auditing $ip..."

            try {
                # Get host key (SSH only)
                $hostKey = $null
                if ($ConnMethod -eq "SSH") {
                    Add-SyncLog -SyncHash $SyncHash -Channel "Audit" -Message "  Getting host key for $ip..."
                    $hostKey = Get-PlinkHostKey -PlinkPath $PlinkPath -IP $ip -Method $ConnMethod
                    if (-not $hostKey) {
                        Add-SyncLog -SyncHash $SyncHash -Channel "Audit" -Message "[ERROR] Could not get host key for $ip"
                        for ($i = 0; $i -lt $results.Count; $i++) {
                            if ($results[$i].IP -eq $ip) {
                                $results[$i].Status = "Failed: No host key"
                                break
                            }
                        }
                        $SyncHash.AuditResults = $results
                        continue
                    }
                }

                # If no stored credentials, try cycling
                if (-not $username) {
                    Add-SyncLog -SyncHash $SyncHash -Channel "Audit" -Message "  No stored credentials, trying all..."
                    foreach ($cred in $Creds) {
                        $username = $cred.Username
                        $password = $cred.Password
                        $enablePass = $cred.EnablePassword
                        $testPsi = New-Object System.Diagnostics.ProcessStartInfo
                        $testPsi.FileName = $PlinkPath
                        if ($ConnMethod -eq "Serial" -or $ConnMethod -eq "Telnet") {
                            $testPsi.Arguments = Build-PlinkArgs -Method $ConnMethod -IP $ip -Username $username `
                                -Password $password -HostKey $hostKey -SerialSettings $SerialSettings
                        } else {
                            $testPsi.Arguments = Build-PlinkArgs -Method $ConnMethod -IP $ip -Username $username `
                                -Password $password -HostKey $hostKey -SerialSettings $SerialSettings -BatchMode
                        }
                        $testPsi.UseShellExecute = $false
                        $testPsi.RedirectStandardOutput = $true
                        $testPsi.RedirectStandardError = $true
                        $testPsi.RedirectStandardInput = $true
                        $testPsi.CreateNoWindow = $true
                        $testProc = [System.Diagnostics.Process]::Start($testPsi)

                        # Start async reads immediately before any stdin writes
                        $testOut = $testProc.StandardOutput.ReadToEndAsync()
                        $testErr = $testProc.StandardError.ReadToEndAsync()

                        if ($ConnMethod -eq "Telnet") {
                            Start-Sleep -Milliseconds 1000
                            $testProc.StandardInput.WriteLine($username)
                            Start-Sleep -Milliseconds 500
                            $testProc.StandardInput.WriteLine($password)
                            Start-Sleep -Milliseconds 1000
                        } elseif ($ConnMethod -eq "Serial") {
                            # Serial console: no login needed, just wait for prompt
                            Start-Sleep -Milliseconds 1000
                        }
                        $testProc.StandardInput.WriteLine("exit")
                        Start-Sleep -Milliseconds 1000
                        $testProc.StandardInput.Close()
                        $testTimeout = if ($ConnMethod -eq "Serial") { 15000 } else { 10000 }
                        if (-not $testProc.WaitForExit($testTimeout)) {
                            try { $testProc.Kill() } catch {}
                        }
                        $outStr = ""; $errStr = ""
                        try { if ($testOut.Wait(3000)) { $outStr = $testOut.Result } } catch {}
                        try { if ($testErr.Wait(3000)) { $errStr = $testErr.Result } } catch {}
                        # Ensure process is fully dead and handle released (critical for serial port)
                        try { if (-not $testProc.HasExited) { $testProc.Kill() } } catch {}
                        try { $testProc.Dispose() } catch {}
                        $combined = "$outStr`n$errStr"
                        if ($combined -notmatch 'Access denied' -and $combined -notmatch 'FATAL ERROR.*password') {
                            Add-SyncLog -SyncHash $SyncHash -Channel "Audit" -Message "  Authenticated with $username"
                            # Wait for OS to release COM port before next plink session
                            if ($ConnMethod -eq "Serial") { Start-Sleep -Milliseconds 1500 }
                            break
                        }
                        # Wait between retries so COM port is freed
                        if ($ConnMethod -eq "Serial") { Start-Sleep -Milliseconds 1000 }
                        $username = $null
                    }
                    if (-not $username) {
                        Add-SyncLog -SyncHash $SyncHash -Channel "Audit" -Message "[ERROR] Auth failed for all credentials on $ip"
                        for ($i = 0; $i -lt $results.Count; $i++) {
                            if ($results[$i].IP -eq $ip) {
                                $results[$i].Status = "Failed: Auth"
                                break
                            }
                        }
                        $SyncHash.AuditResults = $results
                        continue
                    }
                }

                # Build the command sequence depending on device type
                $cmdSequence = @()

                if ($effectiveType -eq "Cisco") {
                    # Enter enable mode and disable pagination
                    $cmdSequence += "enable"
                    $cmdSequence += $enablePass
                    $cmdSequence += "terminal length 0"
                    $cmdSequence += $Commands
                    $cmdSequence += "exit"
                } elseif ($effectiveType -eq "Hirschmann") {
                    # Hirschmann: send commands with spaces for pagination
                    foreach ($cmd in $Commands) {
                        $cmdSequence += $cmd
                        # Add spaces to advance past --More-- prompts
                        $cmdSequence += (" " * 200)
                        $cmdSequence += (" " * 200)
                        $cmdSequence += (" " * 200)
                    }
                    $cmdSequence += "exit"
                } else {
                    # Generic: just send commands
                    $cmdSequence += $Commands
                    $cmdSequence += "exit"
                }

                # Calculate timeout: base 15s + 3s per command; readDelay is final wait after last command
                $auditTimeout = 15000 + ($Commands.Count * 3000)
                if ($auditTimeout -gt 300000) { $auditTimeout = 300000 }
                $readDelay = if ($ConnMethod -eq "Serial") { 5000 + ($Commands.Count * 1000) } else { 5000 + ($Commands.Count * 200) }
                if ($readDelay -gt 30000) { $readDelay = 30000 }

                Add-SyncLog -SyncHash $SyncHash -Channel "Audit" -Message "  Running $($Commands.Count) command(s) on $ip (timeout: $([int]($auditTimeout/1000))s)..."
                $resp = Invoke-PlinkInteractive -PlinkPath $PlinkPath -IP $ip -Username $username `
                    -Password $password -HostKey $hostKey -Commands $cmdSequence `
                    -Timeout $auditTimeout -ReadDelay $readDelay -Method $ConnMethod -SerialSettings $SerialSettings

                # Check for connection errors (ignore benign SSH2_MSG_CHANNEL_EOF when data was received)
                $isFatalErr = $resp.StdErr -match 'FATAL ERROR' -or $resp.StdErr -match 'Access denied'
                $isBenignEOF = $resp.StdErr -match 'SSH2_MSG_CHANNEL_EOF' -and $resp.StdOut.Length -gt 50
                if ($isFatalErr -and -not $isBenignEOF) {
                    Add-SyncLog -SyncHash $SyncHash -Channel "Audit" -Message "[ERROR] Connection error for $ip : $($resp.StdErr.Trim())"
                    for ($i = 0; $i -lt $results.Count; $i++) {
                        if ($results[$i].IP -eq $ip) {
                            $results[$i].Status = "Failed: Connection Error"
                            break
                        }
                    }
                    $SyncHash.AuditResults = $results
                    continue
                }

                # Clean the output
                $cleanedOutput = Clean-AnsiOutput -RawOutput $resp.StdOut

                # Build the output file content with headers
                $sb = New-Object System.Text.StringBuilder
                [void]$sb.AppendLine("=" * 78)
                [void]$sb.AppendLine("  AUDIT REPORT")
                [void]$sb.AppendLine("  Device:   $hostname ($ip)")
                [void]$sb.AppendLine("  Type:     $effectiveType")
                [void]$sb.AppendLine("  Date:     $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
                [void]$sb.AppendLine("  Commands: $($Commands.Count)")
                [void]$sb.AppendLine("=" * 78)
                [void]$sb.AppendLine("")
                [void]$sb.AppendLine($cleanedOutput)

                # Determine filename: hostname_IP_date_time.txt
                $ts = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
                $safeName = Sanitize-Filename -Name $hostname
                $safeIP = $ip -replace ':', '-'
                $fileName = "Audit_${safeName}_${safeIP}_${ts}.txt"
                $filePath = Join-Path $OutputDir $fileName

                [System.IO.File]::WriteAllText($filePath, $sb.ToString(), [System.Text.Encoding]::UTF8)
                Add-SyncLog -SyncHash $SyncHash -Channel "Audit" -Message "  Audit saved: $fileName ($($cleanedOutput.Length) bytes)"

                for ($i = 0; $i -lt $results.Count; $i++) {
                    if ($results[$i].IP -eq $ip) {
                        $results[$i].Status = "Success"
                        $results[$i].Filename = $fileName
                        break
                    }
                }
                $SyncHash.AuditResults = $results

            } catch {
                Add-SyncLog -SyncHash $SyncHash -Channel "Audit" -Message "[ERROR] Exception for $ip : $($_.Exception.Message)"
                $results = $SyncHash.AuditResults
                for ($i = 0; $i -lt $results.Count; $i++) {
                    if ($results[$i].IP -eq $ip) {
                        $results[$i].Status = "Failed: Exception"
                        break
                    }
                }
                $SyncHash.AuditResults = $results
            }
        }

        Add-SyncLog -SyncHash $SyncHash -Channel "Audit" -Message "Audit process complete."
        $SyncHash.AuditComplete = $true
    }).AddArgument($devArray).AddArgument($credsArray).AddArgument($plinkPath).AddArgument($auditDir).AddArgument($sync).AddArgument($connMethod).AddArgument($serialCfg).AddArgument($vendorOvr).AddArgument($commands) | Out-Null

    $auditPS.BeginInvoke() | Out-Null
    $script:activeRunspace = @{ PS = $auditPS; RS = $auditRS }
})

# ---------------------------------------------------------------------------
# Discovery Tab: Event Handlers
# ---------------------------------------------------------------------------

# HiDiscovery v2 Protocol Constants
$script:hdpMulticast = "239.255.16.12"
$script:hdpPort = 51973
$script:hdpCommunity = "@discover@"

# HiDiscovery v2 OIDs (under 1.3.6.1.4.1.248.16.100)
$script:hdpOids = @{
    DevType       = "1.3.6.1.4.1.248.16.100.1.1.0"   # INTEGER - device type
    DevMAC        = "1.3.6.1.4.1.248.16.100.1.2.0"   # OCTET STRING - MAC
    DevConfigSrc  = "1.3.6.1.4.1.248.16.100.1.3.0"   # INTEGER - config source
    DevFirmware   = "1.3.6.1.4.1.248.16.100.1.4.0"   # OCTET STRING - firmware
    DevProduct    = "1.3.6.1.4.1.248.16.100.1.5.0"   # OCTET STRING - product name
    DevIPv6Link   = "1.3.6.1.4.1.248.16.100.1.7.0"   # OCTET STRING - IPv6 link-local
    DevPwdSet     = "1.3.6.1.4.1.248.16.100.1.10.0"  # INTEGER - password set (2=yes)
    NetSerial     = "1.3.6.1.4.1.248.16.100.2.1.0"   # OCTET STRING - serial/ID
    NetHDP        = "1.3.6.1.4.1.248.16.100.2.2.0"   # INTEGER - HiDiscovery enabled
    NetCfgStatus  = "1.3.6.1.4.1.248.16.100.2.3.0"   # INTEGER - config status
    NetIPAddr     = "1.3.6.1.4.1.248.16.100.2.4.0"   # IpAddress - IP address
    NetPrefixLen  = "1.3.6.1.4.1.248.16.100.2.5.0"   # Gauge32 - prefix length
    NetDHCP       = "1.3.6.1.4.1.248.16.100.2.6.0"   # INTEGER
    NetGateway    = "1.3.6.1.4.1.248.16.100.2.7.0"   # IpAddress - gateway
    NetAction     = "1.3.6.1.4.1.248.16.100.2.9.0"   # INTEGER - action trigger
    SysName       = "1.3.6.1.2.1.1.5.0"              # sysName
}

# -- Discovery Scan (HiDiscovery v2 multicast) --
$btnDiscScan.Add_Click({
    # Clean up previous discovery runspace
    if ($script:discoveryRunspace) {
        try {
            if ($script:discoveryRunspace.PS) { $script:discoveryRunspace.PS.Stop(); $script:discoveryRunspace.PS.Dispose() }
            if ($script:discoveryRunspace.RS) { $script:discoveryRunspace.RS.Close(); $script:discoveryRunspace.RS.Dispose() }
        } catch {}
        $script:discoveryRunspace = $null
    }

    $sync.DiscoveryCancel = $false
    $sync.DiscoveryResults = @()
    $sync.DiscoveryStatus = "Sending HiDiscovery v2 multicast..."
    $sync.DiscoveryComplete = $false
    $sync.DiscoveryLog = @()
    $sync.DiscoveryLogIndex = 0

    $dgvDiscovery.Rows.Clear()
    $rtbDiscLog.Clear()
    $btnDiscScan.Enabled = $false
    $btnDiscStop.Enabled = $true
    $progressDisc.MarqueeAnimationSpeed = 30

    $timeoutSec = [int]$numDiscTimeout.Value

    # Get selected NIC IP for binding
    $localIP = "0.0.0.0"
    if ($cboDiscNic.SelectedIndex -ge 0 -and $cboDiscNic.Tag -and $cboDiscNic.Tag.Count -gt $cboDiscNic.SelectedIndex) {
        $nicInfo = $cboDiscNic.Tag[$cboDiscNic.SelectedIndex]
        if ($nicInfo.IP) { $localIP = $nicInfo.IP }
    }

    # Build the HiDiscovery v2 GET request packet
    $hdpOidList = @(
        "1.3.6.1.4.1.248.16.100.1.1.0",
        "1.3.6.1.4.1.248.16.100.1.2.0",
        "1.3.6.1.4.1.248.16.100.1.3.0",
        "1.3.6.1.4.1.248.16.100.1.4.0",
        "1.3.6.1.4.1.248.16.100.1.5.0",
        "1.3.6.1.4.1.248.16.100.1.7.0",
        "1.3.6.1.4.1.248.16.100.1.10.0",
        "1.3.6.1.4.1.248.16.100.2.1.0",
        "1.3.6.1.4.1.248.16.100.2.2.0",
        "1.3.6.1.4.1.248.16.100.2.3.0",
        "1.3.6.1.4.1.248.16.100.2.4.0",
        "1.3.6.1.4.1.248.16.100.2.5.0",
        "1.3.6.1.4.1.248.16.100.2.6.0",
        "1.3.6.1.4.1.248.16.100.2.7.0",
        "1.3.6.1.4.1.248.16.100.2.9.0",
        "1.3.6.1.2.1.1.5.0"
    )
    $discoveryPacket = Build-SnmpGetRequest -Community "@discover@" -Oids $hdpOidList -RequestId 0

    # Launch background runspace to send multicast and collect responses
    $discRS = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace($script:sharedISS)
    $discRS.Open()
    $discPS = [PowerShell]::Create()
    $discPS.Runspace = $discRS

    $null = $discPS.AddScript({
        param([byte[]]$Packet, [string]$LocalIP, [int]$TimeoutSec, [hashtable]$SyncHash, [bool]$DoSsh, $CredsArray, [string]$PlinkPath)

        function ParseResponseInner {
            param([byte[]]$Data)
            try {
                if ($Data.Count -lt 2 -or $Data[0] -ne 0x30) { return $null }
                $pos = 1
                # Sequence length
                $fb = $Data[$pos]
                if ($fb -lt 128) { $seqLen = [int]$fb; $pos += 1 }
                else { $n = $fb -band 0x7F; $seqLen = 0; for ($j = 0; $j -lt $n; $j++) { $seqLen = ($seqLen -shl 8) + $Data[$pos+1+$j] }; $pos += 1 + $n }
                # Version
                $pos++; $vl = [int]$Data[$pos]; $pos += 1 + $vl
                # Community
                $pos++; $fb2 = $Data[$pos]
                if ($fb2 -lt 128) { $cl = [int]$fb2; $pos += 1 } else { $n2 = $fb2 -band 0x7F; $cl = 0; for ($j = 0; $j -lt $n2; $j++) { $cl = ($cl -shl 8) + $Data[$pos+1+$j] }; $pos += 1+$n2 }
                $pos += $cl
                # PDU tag (0xA2 = GetResponse)
                $pduTag = $Data[$pos]; $pos++
                $fb3 = $Data[$pos]
                if ($fb3 -lt 128) { $pduLen = [int]$fb3; $pos += 1 } else { $n3 = $fb3 -band 0x7F; $pduLen = 0; for ($j = 0; $j -lt $n3; $j++) { $pduLen = ($pduLen -shl 8) + $Data[$pos+1+$j] }; $pos += 1+$n3 }
                # ReqID
                $pos++; $rl = [int]$Data[$pos]; $pos += 1 + $rl
                # ErrorStatus
                $pos++; $el = [int]$Data[$pos]; $pos += 1
                $errStat = 0; for ($j = 0; $j -lt $el; $j++) { $errStat = ($errStat -shl 8) + $Data[$pos+$j] }; $pos += $el
                # ErrorIndex
                $pos++; $eil = [int]$Data[$pos]; $pos += 1 + $eil
                # VarbindList
                if ($pos -ge $Data.Count -or $Data[$pos] -ne 0x30) { return $null }; $pos++
                $fb4 = $Data[$pos]
                if ($fb4 -lt 128) { $vblLen = [int]$fb4; $pos += 1 } else { $n4 = $fb4 -band 0x7F; $vblLen = 0; for ($j = 0; $j -lt $n4; $j++) { $vblLen = ($vblLen -shl 8) + $Data[$pos+1+$j] }; $pos += 1+$n4 }
                $vblEnd = $pos + $vblLen
                $results = @{}
                while ($pos -lt $vblEnd -and $pos -lt $Data.Count) {
                    if ($Data[$pos] -ne 0x30) { break }; $pos++
                    $fb5 = $Data[$pos]
                    if ($fb5 -lt 128) { $vbLen = [int]$fb5; $pos += 1 } else { $n5 = $fb5 -band 0x7F; $vbLen = 0; for ($j = 0; $j -lt $n5; $j++) { $vbLen = ($vbLen -shl 8) + $Data[$pos+1+$j] }; $pos += 1+$n5 }
                    $vbEnd = $pos + $vbLen
                    # OID
                    if ($Data[$pos] -ne 0x06) { $pos = $vbEnd; continue }; $pos++
                    $oidLen = [int]$Data[$pos]; $pos++
                    $oidBytes = $Data[$pos..($pos+$oidLen-1)]
                    # Decode OID
                    $oidParts = [System.Collections.ArrayList]::new()
                    $null = $oidParts.Add([Math]::Floor($oidBytes[0]/40))
                    $null = $oidParts.Add($oidBytes[0]%40)
                    $oi = 1
                    while ($oi -lt $oidBytes.Count) {
                        $ov = 0
                        while ($oi -lt $oidBytes.Count) {
                            $ob = $oidBytes[$oi]; $oi++
                            $ov = ($ov -shl 7) -bor ($ob -band 0x7F)
                            if (($ob -band 0x80) -eq 0) { break }
                        }
                        $null = $oidParts.Add($ov)
                    }
                    $oid = $oidParts -join '.'
                    $pos += $oidLen
                    # Value
                    $vtag = $Data[$pos]; $pos++
                    $fb6 = $Data[$pos]
                    if ($fb6 -lt 128) { $valLen = [int]$fb6; $pos += 1 } else { $n6 = $fb6 -band 0x7F; $valLen = 0; for ($j = 0; $j -lt $n6; $j++) { $valLen = ($valLen -shl 8) + $Data[$pos+1+$j] }; $pos += 1+$n6 }
                    $valBytes = if ($valLen -gt 0 -and ($pos+$valLen-1) -lt $Data.Count) { $Data[$pos..($pos+$valLen-1)] } else { @() }
                    $value = $null
                    switch ($vtag) {
                        0x02 { $iv = 0; foreach ($b in $valBytes) { $iv = ($iv -shl 8) + $b }; $value = $iv }
                        0x04 {
                            # OID-aware decoding for known binary OCTET STRING fields
                            if ($oid -eq "1.3.6.1.4.1.248.16.100.1.2.0" -and $valBytes.Count -eq 6) {
                                # MAC address: always format as hex
                                $value = ($valBytes | ForEach-Object { $_.ToString("X2") }) -join ':'
                            } elseif (($oid -eq "1.3.6.1.4.1.248.16.100.2.4.0" -or $oid -eq "1.3.6.1.4.1.248.16.100.2.7.0") -and $valBytes.Count -eq 4) {
                                # IP Address / Gateway returned as OCTET STRING: format as dotted decimal
                                $value = "$($valBytes[0]).$($valBytes[1]).$($valBytes[2]).$($valBytes[3])"
                            } else {
                                $pr = $true; foreach ($b in $valBytes) { if (($b -lt 0x20 -and $b -ne 0x0A -and $b -ne 0x0D -and $b -ne 0x09) -or $b -gt 0x7E) { $pr = $false; break } }
                                if ($pr -and $valBytes.Count -gt 0) { $value = [System.Text.Encoding]::ASCII.GetString([byte[]]$valBytes) }
                                else { $value = ($valBytes | ForEach-Object { $_.ToString("X2") }) -join ':' }
                            }
                        }
                        0x40 { if ($valBytes.Count -eq 4) { $value = "$($valBytes[0]).$($valBytes[1]).$($valBytes[2]).$($valBytes[3])" } }
                        0x42 { $uv = [uint32]0; foreach ($b in $valBytes) { $uv = ($uv -shl 8) + $b }; $value = $uv }
                        0x80 { $value = $null }
                        0x81 { $value = $null }
                        default { $value = ($valBytes | ForEach-Object { $_.ToString("X2") }) -join ':' }
                    }
                    $results[$oid] = $value
                    $pos = $vbEnd
                }
                return $results
            } catch { return $null }
        }

        Add-SyncLog -SyncHash $SyncHash -Channel "Discovery" -Message "HiDiscovery v2 scan starting..."
        Add-SyncLog -SyncHash $SyncHash -Channel "Discovery" -Message "Multicast: 239.255.16.12:51973, Community: @discover@"
        Add-SyncLog -SyncHash $SyncHash -Channel "Discovery" -Message "Binding to local IP: $LocalIP"
        $SyncHash.DiscoveryStatus = "Listening for HiDiscovery v2 responses..."

        try {
            # Create UDP socket, bind to local NIC, join multicast group
            $udp = New-Object System.Net.Sockets.UdpClient
            $udp.Client.SetSocketOption([System.Net.Sockets.SocketOptionLevel]::Socket, [System.Net.Sockets.SocketOptionName]::ReuseAddress, $true)
            $localEP = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($LocalIP), 0)
            $udp.Client.Bind($localEP)
            $udp.JoinMulticastGroup([System.Net.IPAddress]::Parse("239.255.16.12"), [System.Net.IPAddress]::Parse($LocalIP))
            $udp.Client.ReceiveTimeout = 2000

            # Send discovery packet to multicast group
            $mcastEP = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse("239.255.16.12"), 51973)
            $null = $udp.Send($Packet, $Packet.Length, $mcastEP)
            Add-SyncLog -SyncHash $SyncHash -Channel "Discovery" -Message "Discovery packet sent ($($Packet.Length) bytes)"

            # Listen for responses
            $devices = @{}
            $deadline = (Get-Date).AddSeconds($TimeoutSec)
            while ((Get-Date) -lt $deadline -and -not $SyncHash.DiscoveryCancel) {
                try {
                    $remoteEP = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
                    $response = $udp.Receive([ref]$remoteEP)
                    if ($response -and $response.Count -gt 10) {
                        $srcIP = $remoteEP.Address.ToString()
                        if ($srcIP -eq $LocalIP) { continue }  # Skip our own multicast

                        $parsed = ParseResponseInner -Data $response
                        if ($parsed -and $parsed.Count -gt 0) {
                            # Extract fields
                            $mac = ""
                            if ($parsed.ContainsKey("1.3.6.1.4.1.248.16.100.1.2.0")) {
                                $mac = $parsed["1.3.6.1.4.1.248.16.100.1.2.0"]
                            }
                            $firmware = ""
                            if ($parsed.ContainsKey("1.3.6.1.4.1.248.16.100.1.4.0")) {
                                $firmware = $parsed["1.3.6.1.4.1.248.16.100.1.4.0"]
                            }
                            $product = ""
                            if ($parsed.ContainsKey("1.3.6.1.4.1.248.16.100.1.5.0")) {
                                $product = $parsed["1.3.6.1.4.1.248.16.100.1.5.0"]
                            }
                            $serial = ""
                            if ($parsed.ContainsKey("1.3.6.1.4.1.248.16.100.2.1.0")) {
                                $serial = $parsed["1.3.6.1.4.1.248.16.100.2.1.0"]
                            }
                            $ipAddr = $srcIP
                            if ($parsed.ContainsKey("1.3.6.1.4.1.248.16.100.2.4.0") -and $parsed["1.3.6.1.4.1.248.16.100.2.4.0"]) {
                                $ipAddr = $parsed["1.3.6.1.4.1.248.16.100.2.4.0"]
                            }
                            $prefixLen = 24
                            if ($parsed.ContainsKey("1.3.6.1.4.1.248.16.100.2.5.0") -and $parsed["1.3.6.1.4.1.248.16.100.2.5.0"]) {
                                $prefixLen = [int]$parsed["1.3.6.1.4.1.248.16.100.2.5.0"]
                            }
                            $gateway = "0.0.0.0"
                            if ($parsed.ContainsKey("1.3.6.1.4.1.248.16.100.2.7.0") -and $parsed["1.3.6.1.4.1.248.16.100.2.7.0"]) {
                                $gateway = $parsed["1.3.6.1.4.1.248.16.100.2.7.0"]
                            }
                            $hostname = ""
                            if ($parsed.ContainsKey("1.3.6.1.2.1.1.5.0") -and $parsed["1.3.6.1.2.1.1.5.0"]) {
                                $hostname = $parsed["1.3.6.1.2.1.1.5.0"]
                            }
                            $cfgStatus = 0
                            if ($parsed.ContainsKey("1.3.6.1.4.1.248.16.100.2.3.0")) {
                                $cfgStatus = $parsed["1.3.6.1.4.1.248.16.100.2.3.0"]
                            }
                            $pwdSet = 0
                            if ($parsed.ContainsKey("1.3.6.1.4.1.248.16.100.1.10.0")) {
                                $pwdSet = $parsed["1.3.6.1.4.1.248.16.100.1.10.0"]
                            }

                            $netmask = PrefixToMask -Prefix $prefixLen

                            # Use MAC as unique key to avoid duplicates
                            $key = if ($mac) { $mac } else { $srcIP }
                            if (-not $devices.ContainsKey($key)) {
                                $devices[$key] = @{
                                    IP           = $ipAddr
                                    MAC          = $mac
                                    Product      = $product
                                    Firmware     = $firmware
                                    Hostname     = $hostname
                                    Netmask      = $netmask
                                    Gateway      = $gateway
                                    Serial       = $serial
                                    ConfigStatus = $cfgStatus
                                    PasswordSet  = $pwdSet
                                }
                                Add-SyncLog -SyncHash $SyncHash -Channel "Discovery" -Message "Found: $product at $ipAddr (MAC: $mac)"
                                $SyncHash.DiscoveryStatus = "Found $($devices.Count) device(s)... listening..."
                            }
                        }
                    }
                } catch [System.Net.Sockets.SocketException] {
                    # Timeout — continue listening until deadline
                }
            }

            $udp.DropMulticastGroup([System.Net.IPAddress]::Parse("239.255.16.12"))
            $udp.Close()
        } catch {
            Add-SyncLog -SyncHash $SyncHash -Channel "Discovery" -Message "ERROR: $($_.Exception.Message)"
        }

        if ($SyncHash.DiscoveryCancel) {
            Add-SyncLog -SyncHash $SyncHash -Channel "Discovery" -Message "Discovery cancelled."
            $SyncHash.DiscoveryStatus = "Cancelled."
        } else {
            $SyncHash.DiscoveryResults = @($devices.Values)
            Add-SyncLog -SyncHash $SyncHash -Channel "Discovery" -Message "Discovery complete. Found $($devices.Count) Hirschmann device(s)."
        }
        $SyncHash.DiscoveryComplete = $true
    }).AddArgument($discoveryPacket).AddArgument($localIP).AddArgument($timeoutSec).AddArgument($sync).AddArgument($chkDiscSsh.Checked).AddArgument(@()).AddArgument("")

    $null = $discPS.BeginInvoke()
    $script:discoveryRunspace = @{ PS = $discPS; RS = $discRS }
})

# -- Discovery Stop --
$btnDiscStop.Add_Click({
    $sync.DiscoveryCancel = $true
    $btnDiscStop.Enabled = $false
    $lblDiscStatus.Text = "Cancelling..."
})

# -- Discovery: Apply IP Config via HiDiscovery v2 multicast SET --
$btnDiscApplyIP.Add_Click({
    if ($dgvDiscovery.SelectedRows.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("Select a device in the grid first.", "No Selection")
        return
    }
    $row = $dgvDiscovery.SelectedRows[0]
    $deviceIP = $row.Cells["IPAddress"].Value
    $deviceSerial = $row.Cells["Serial"].Value
    $newIP = $txtDiscNewIP.Text.Trim()
    $newMask = $txtDiscNewMask.Text.Trim()
    $newGateway = $txtDiscNewGateway.Text.Trim()
    $newName = $txtDiscNewName.Text.Trim()

    if (-not $newIP -and -not $newName) {
        [System.Windows.Forms.MessageBox]::Show("Enter at least a new IP address or device name.", "Input Required")
        return
    }
    if (-not $deviceSerial) {
        [System.Windows.Forms.MessageBox]::Show("Device serial number not available. Cannot apply configuration via HiDiscovery.", "Error")
        return
    }

    $confirm = [System.Windows.Forms.MessageBox]::Show(
        "Apply HiDiscovery v2 configuration?`n`nDevice: $deviceIP (Serial: $deviceSerial)`nNew IP: $(if($newIP){$newIP}else{'(unchanged)'})`nMask: $(if($newMask){$newMask}else{'(unchanged)'})`nGateway: $(if($newGateway){$newGateway}else{'(unchanged)'})",
        "Confirm Configuration Change",
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Warning
    )
    if ($confirm -ne 'Yes') { return }

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $rtbDiscLog.AppendText("[$timestamp] Applying HiDiscovery v2 config to $deviceIP (serial: $deviceSerial)...`n")

    # Build multicast SNMP SET packet matching HiView's format
    # Varbinds: Serial (key), CfgStatus=1, IP, HDP=1, Action=2
    $varbinds = [byte[]]@()
    # Serial number (identifier)
    $varbinds += Build-SnmpVarbind -Oid "1.3.6.1.4.1.248.16.100.2.1.0" -ValueTlv (Build-BerOctetString -Value $deviceSerial)
    # Config status = 1 (configured)
    $varbinds += Build-SnmpVarbind -Oid "1.3.6.1.4.1.248.16.100.2.3.0" -ValueTlv (Build-BerInteger -Value 1)
    # IP Address
    if ($newIP) {
        $varbinds += Build-SnmpVarbind -Oid "1.3.6.1.4.1.248.16.100.2.4.0" -ValueTlv (Build-BerIpAddress -IP $newIP)
    }
    # HDP enabled = 1
    $varbinds += Build-SnmpVarbind -Oid "1.3.6.1.4.1.248.16.100.2.2.0" -ValueTlv (Build-BerInteger -Value 1)
    # Action trigger = 2 (apply)
    $varbinds += Build-SnmpVarbind -Oid "1.3.6.1.4.1.248.16.100.2.8.0" -ValueTlv (Build-BerInteger -Value 2)

    $varbindList = Build-BerSequence -Content $varbinds
    $reqIdBer = Build-BerInteger -Value 0
    $errorStatusBer = Build-BerInteger -Value 0
    $errorIndexBer = Build-BerInteger -Value 0
    $pduContent = $reqIdBer + $errorStatusBer + $errorIndexBer + $varbindList
    $pduLenBytes = ConvertTo-BerLength -Length $pduContent.Count
    $pdu = [byte[]]@(0xA3) + $pduLenBytes + $pduContent  # SetRequest

    $versionBer = Build-BerInteger -Value 1
    $communityBer = Build-BerOctetString -Value "@discover@"
    $messageContent = $versionBer + $communityBer + $pdu
    $setPacket = Build-BerSequence -Content $messageContent

    # Send via multicast (same as HiView does)
    try {
        $localIP = "0.0.0.0"
        if ($cboDiscNic.SelectedIndex -ge 0 -and $cboDiscNic.Tag -and $cboDiscNic.Tag.Count -gt $cboDiscNic.SelectedIndex) {
            $nicInfo = $cboDiscNic.Tag[$cboDiscNic.SelectedIndex]
            if ($nicInfo.IP) { $localIP = $nicInfo.IP }
        }

        $udp = New-Object System.Net.Sockets.UdpClient
        $localEP = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($localIP), 0)
        $udp.Client.Bind($localEP)
        $mcastEP = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse("239.255.16.12"), 51973)
        $null = $udp.Send($setPacket, $setPacket.Length, $mcastEP)
        $udp.Close()

        $rtbDiscLog.AppendText("[$timestamp]   SET packet sent via multicast ($($setPacket.Length) bytes)`n")
        $rtbDiscLog.AppendText("[$timestamp]   Configuration applied. Re-scan to verify changes.`n")
    } catch {
        $rtbDiscLog.AppendText("[$timestamp]   ERROR sending SET: $($_.Exception.Message)`n")
    }
    $rtbDiscLog.ScrollToCaret()
})

# -- Discovery: Flash LED --
$btnDiscFlashLED.Add_Click({
    if ($dgvDiscovery.SelectedRows.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("Select a device in the grid first.", "No Selection")
        return
    }
    $row = $dgvDiscovery.SelectedRows[0]
    $deviceIP = $row.Cells["IPAddress"].Value
    $writeCommunity = "private"

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $rtbDiscLog.AppendText("[$timestamp] Flashing LED on $deviceIP...`n")

    # Hirschmann signal LED OID: hmSysLED = 1.3.6.1.4.1.248.14.1.2.1.0
    # Value 1 = on, value 2 = off (or similar, varies by model)
    # Try hmSysGroupSignalLED: 1.3.6.1.4.1.248.14.1.1.9.0  (1=enable, 2=disable)
    $ledOnTlv = Build-BerInteger -Value 1
    $result = Invoke-SnmpSet -IP $deviceIP -Oid "1.3.6.1.4.1.248.14.1.1.9.0" -ValueTlv $ledOnTlv -Community $writeCommunity -TimeoutMs 3000
    if ($result -and $result.ErrorStatus -eq 0) {
        $rtbDiscLog.AppendText("[$timestamp]   Signal LED activated on $deviceIP`n")
        $rtbDiscLog.AppendText("[$timestamp]   LED will flash for ~30 seconds (device-dependent).`n")
    } else {
        $errCode = if ($result) { $result.ErrorStatus } else { "No response" }
        $rtbDiscLog.AppendText("[$timestamp]   LED flash FAILED (error: $errCode). Device may not support this OID.`n")
        # Try alternative OID
        $result2 = Invoke-SnmpSet -IP $deviceIP -Oid "1.3.6.1.4.1.248.14.1.2.1.0" -ValueTlv $ledOnTlv -Community $writeCommunity -TimeoutMs 3000
        if ($result2 -and $result2.ErrorStatus -eq 0) {
            $rtbDiscLog.AppendText("[$timestamp]   Signal LED activated via alternate OID.`n")
        } else {
            $rtbDiscLog.AppendText("[$timestamp]   Alternate OID also failed. Check write community and device support.`n")
        }
    }
    $rtbDiscLog.ScrollToCaret()
})

# -- Discovery: Open Web UI --
$btnDiscOpenWeb.Add_Click({
    if ($dgvDiscovery.SelectedRows.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("Select a device in the grid first.", "No Selection")
        return
    }
    $row = $dgvDiscovery.SelectedRows[0]
    $deviceIP = $row.Cells["IPAddress"].Value
    if ($deviceIP) {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $rtbDiscLog.AppendText("[$timestamp] Opening web UI for $deviceIP...`n")
        $rtbDiscLog.ScrollToCaret()
        Start-Process "http://$deviceIP"
    }
})

# -- Discovery: Change Password via SSH --
$btnDiscChangePwd.Add_Click({
    if ($dgvDiscovery.SelectedRows.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("Select a device in the grid first.", "No Selection")
        return
    }
    $row = $dgvDiscovery.SelectedRows[0]
    $deviceIP = $row.Cells["IPAddress"].Value
    $newPwd = $txtDiscNewPassword.Text
    $newEnable = $txtDiscNewEnable.Text

    if (-not $newPwd -and -not $newEnable) {
        [System.Windows.Forms.MessageBox]::Show("Enter a new password or enable password.", "Input Required")
        return
    }
    if ($script:credentials.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No credentials configured. Add credentials in the Credentials tab first.", "No Credentials")
        return
    }

    $plinkPath = Find-Plink
    if (-not $plinkPath) {
        [System.Windows.Forms.MessageBox]::Show("plink.exe not found. Install PuTTY or place plink.exe in the app directory.", "Plink Not Found")
        return
    }

    $confirm = [System.Windows.Forms.MessageBox]::Show(
        "Change password on $deviceIP`?`n`nNew Password: $(if($newPwd){'(set)'}else{'(unchanged)'})`nNew Enable: $(if($newEnable){'(set)'}else{'(unchanged)'})`n`nThis will SSH into the device using credentials from the Credentials tab.",
        "Confirm Password Change",
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Warning
    )
    if ($confirm -ne 'Yes') { return }

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $rtbDiscLog.AppendText("[$timestamp] Changing password on $deviceIP...`n")
    $rtbDiscLog.ScrollToCaret()

    # Get host key
    $hostKey = Get-PlinkHostKey -PlinkPath $plinkPath -IP $deviceIP
    if (-not $hostKey) {
        $rtbDiscLog.AppendText("[$timestamp]   ERROR: Could not get SSH host key.`n")
        $rtbDiscLog.ScrollToCaret()
        return
    }

    # Try each credential
    $success = $false
    foreach ($cred in $script:credentials) {
        $commands = @()
        if ($newPwd) {
            # Hirschmann CLI: change user password
            $commands += "users password admin `"$newPwd`""
        }
        if ($newEnable) {
            # Hirschmann CLI: change enable password (if applicable)
            $commands += "users password enable `"$newEnable`""
        }
        $commands += "exit"

        $result = Invoke-PlinkInteractive -PlinkPath $plinkPath -IP $deviceIP `
            -Username $cred.Username -Password $cred.Password -HostKey $hostKey `
            -Commands $commands -Timeout 15000 -ReadDelay 3000

        if ($result.StdOut -and $result.StdOut -notmatch 'Access denied' -and $result.ExitCode -ne 1) {
            $success = $true
            $rtbDiscLog.AppendText("[$timestamp]   Password changed successfully on $deviceIP`n")
            break
        }
    }

    if (-not $success) {
        $rtbDiscLog.AppendText("[$timestamp]   ERROR: Failed to change password. Check credentials and device access.`n")
    }
    $rtbDiscLog.ScrollToCaret()
})

# -- Form Closing: cleanup --
$form.Add_FormClosing({
    $sync.Cancel = $true
    $sync.WatchdogCancel = $true
    $sync.DiscoveryCancel = $true
    $uiTimer.Stop()
    $uiTimer.Dispose()

    # Give background threads a moment to notice the cancel flag
    Start-Sleep -Milliseconds 500

    if ($script:runspacePool) {
        try { $script:runspacePool.Close(); $script:runspacePool.Dispose() } catch {}
    }
    if ($script:activeRunspace) {
        try {
            if ($script:activeRunspace.PS) { $script:activeRunspace.PS.Stop(); $script:activeRunspace.PS.Dispose() }
            if ($script:activeRunspace.RS) { $script:activeRunspace.RS.Close(); $script:activeRunspace.RS.Dispose() }
            if ($script:activeRunspace.Pool) { $script:activeRunspace.Pool.Close(); $script:activeRunspace.Pool.Dispose() }
        } catch {}
    }
    if ($script:watchdogRunspace) {
        try {
            if ($script:watchdogRunspace.PS) { $script:watchdogRunspace.PS.Stop(); $script:watchdogRunspace.PS.Dispose() }
            if ($script:watchdogRunspace.RS) { $script:watchdogRunspace.RS.Close(); $script:watchdogRunspace.RS.Dispose() }
        } catch {}
    }
    if ($script:discoveryRunspace) {
        try {
            if ($script:discoveryRunspace.PS) { $script:discoveryRunspace.PS.Stop(); $script:discoveryRunspace.PS.Dispose() }
            if ($script:discoveryRunspace.RS) { $script:discoveryRunspace.RS.Close(); $script:discoveryRunspace.RS.Dispose() }
            if ($script:discoveryRunspace.Pool) { $script:discoveryRunspace.Pool.Close(); $script:discoveryRunspace.Pool.Dispose() }
        } catch {}
    }
})

# ---------------------------------------------------------------------------
# Theme Selection Handler
# ---------------------------------------------------------------------------
$cboTheme.Add_SelectedIndexChanged({
    $themeName = $cboTheme.SelectedItem.ToString()
    Apply-Theme -ThemeName $themeName
    # Keep scan grid selection invisible so ping dots remain visible
    $dgvScan.DefaultCellStyle.SelectionBackColor = $dgvScan.DefaultCellStyle.BackColor
    $dgvScan.DefaultCellStyle.SelectionForeColor = $dgvScan.DefaultCellStyle.ForeColor
})

# Apply default theme on startup
Apply-Theme -ThemeName 'Light'
$dgvScan.DefaultCellStyle.SelectionBackColor = $dgvScan.DefaultCellStyle.BackColor
$dgvScan.DefaultCellStyle.SelectionForeColor = $dgvScan.DefaultCellStyle.ForeColor

# ---------------------------------------------------------------------------
# Launch
# ---------------------------------------------------------------------------
[System.Windows.Forms.Application]::Run($form)
