Set WshShell = CreateObject("WScript.Shell")
WshShell.Run "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File """ & CreateObject("Scripting.FileSystemObject").GetParentFolderName(WScript.ScriptFullName) & "\SwitchConfigBackup.ps1""", 0, False
