REM This file is intended to be used when the toast notification script is used with scheduled tasks with the Hidden.vbs file. See the documentation for further details

IF "%PROCESSOR_ARCHITEW6432%" == "AMD64" (
SET pspath="C:\Windows\SysNative\WindowsPowerShell\v1.0\powershell.exe"
) ELSE (
SET pspath="C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
)
%pspath% -file "C:\ProgramData\ToastNotificationScript\PendingReboot\New-ToastNotification.ps1" -Config "\\YourNetworkPath\ToastNotificationScript\Configs\config-toast-pendingreboot.xml"
