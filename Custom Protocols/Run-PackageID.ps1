<#
.SYNOPSIS
    Script used to execute packages and task sequences directly from my Windows 10 Toast Notification Script
   
.NOTES
    Filename: Run-PackageID.ps1
    Version: 1.0
    Author: Martin Bengtsson
    Blog: www.imab.dk
    Twitter: @mwbengtsson

.LINKS
    https://www.imab.dk/windows-10-toast-notification-script
#> 

$RegistryPath = "HKCU:\SOFTWARE\ToastNotificationScript"
$PackageID = (Get-ItemProperty -Path $RegistryPath -Name "RunPackageID").RunPackageID
$SoftwareCenter = New-Object -ComObject "UIResource.UIResourceMgr"
$ProgramID = "*"
$SoftwareCenter.ExecuteProgram($ProgramID,$PackageID,$true)