<#
.SYNOPSIS
    Script used to execute applications directly from my Windows 10 Toast Notification Script
   
.NOTES
    Filename: Run-ApplicationID.ps1
    Version: 1.0
    Author: Martin Bengtsson
    Blog: www.imab.dk
    Twitter: @mwbengtsson

.LINKS
    https://www.imab.dk/windows-10-toast-notification-script
#> 

# Function for triggering the installation or reparing of applications
# Parts of this function is heavily inspired by Timmy's post at: https://timmyit.com/2016/08/08/sccm-and-powershell-force-installuninstall-of-available-software-in-software-center-through-cimwmi-on-a-remote-client/
# Function is modified to cater for a scenario where the application needs repairing instead of installing
# Also removed bits and pieces which I don't need :-)
function Trigger-AppInstallation() {
    param(
        [String][Parameter(Mandatory=$true)] $appID
    )
 
    Begin {
        $application = (Get-CimInstance -ClassName CCM_Application -Namespace "root\ccm\clientSDK" | Where-Object {$_.Id -eq $appID})
        $args = @{EnforcePreference = [UINT32] 0
        Id = "$($application.Id)"
        IsMachineTarget = $application.IsMachineTarget
        IsRebootIfNeeded = $false
        Priority = 'High'
        Revision = "$($application.Revision)"}
     }
 
    Process {
        if ($application.InstallState -eq "NotInstalled") {
            try {
                Invoke-CimMethod -Namespace "root\ccm\clientSDK" -ClassName CCM_Application -MethodName Install -Arguments $args
            }
            catch { }
        }
        elseif ($application.InstallState -eq "Installed") {
            try {
                Invoke-CimMethod -Namespace "root\ccm\clientSDK" -ClassName CCM_Application -MethodName Repair -Arguments $args
            }
            catch { }
        }
    }
 
    End { }
}
$registryPath = "HKCU:\SOFTWARE\ToastNotificationScript"
$applicationID = (Get-ItemProperty -Path $RegistryPath -Name "RunApplicationID").RunApplicationID
Trigger-AppInstallation -appID $applicationID