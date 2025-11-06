<#
.SYNOPSIS
    Detect-ToastNotification.ps1 - Detection Script for Toast Notification Script for Microsoft Intune

.DESCRIPTION
    Detection script for Toast Notification Script in Microsoft Intune.
    Detects if conditions are met for displaying the toast notification.

.PARAMETER Config
    Path or URL to the XML configuration file.
    Default: "https://toast.imab.dk/config-toast-pendingreboot.xml"

.OUTPUTS
    Exit codes for Microsoft Intune detection:
    • 0: No action needed
      - All relevant features are disabled in configuration
      - Detection conditions are not met (e.g., uptime below threshold)
      - WeeklyMessage not triggered (wrong day/hour)
      - Configuration conflicts prevent execution
    • 1: Action needed
      - One or more detection conditions are met
      - WeeklyMessage should be triggered (correct day/hour)
      - PendingRebootUptime threshold exceeded
      - Toast notification should be displayed

.NOTES
    Script Name    : Detect-ToastNotification.ps1
    Version        : 3.0.0
    Author         : Martin Bengtsson, Rewritten for Microsoft Intune
    Created        : November 2025
    Updated        : November 2025
    
    Requirements:
    • Windows 10 version 1709 or later / Windows 11
    • PowerShell 5.1 or later
    • Microsoft Intune managed device
    • User context execution (not SYSTEM)
    • Internet connectivity for online configuration files
    
    Intune Deployment:
    • Deploy as detection script with remediation script: Remediate-ToastNotification.ps1
    • Configure appropriate schedule based on notification requirements
    • Ensure proper user assignment and targeting

.LINK
    https://www.imab.dk/windows-10-toast-notification-script/

.LINK
    https://github.com/imabdk/Toast-Notification-Script

#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$Config = "https://toast.imab.dk/config-toast-pendingreboot.xml"
    #[string]$Config = "https://toast.imab.dk/config-toast-weeklymessage.xml"
)

# Create Get-DeviceUptime function (same as main script)
function Get-DeviceUptime() {
    $OS = Get-CimInstance Win32_OperatingSystem
    $Uptime = (Get-Date) - ($OS.LastBootUptime)
    $Uptime.Days
}

# Function to check for configuration conflicts
function Test-ConfigConflicts() {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [xml]$ConfigXml
    )
    
    $Conflicts = @()
    
    # Check if Toast feature is globally disabled (should be first check)
    $ToastEnabled = ($ConfigXml.Configuration.Feature | Where-Object {$_.Name -eq "Toast"}).Enabled
    if ($ToastEnabled -ne "True") {
        $Conflicts += "Toast feature is disabled in configuration (Toast Enabled = '$ToastEnabled') - no notifications can be displayed"
        return $Conflicts  # Return early if Toast is disabled
    }
    
    # Only check other conflicts if Toast is enabled
    # Check for multiple trigger features enabled simultaneously
    $PendingRebootEnabled = ($ConfigXml.Configuration.Feature | Where-Object {$_.Name -eq "PendingRebootUptime"}).Enabled
    $WeeklyMessageEnabled = ($ConfigXml.Configuration.Feature | Where-Object {$_.Name -eq "WeeklyMessage"}).Enabled
    
    if ($PendingRebootEnabled -eq "True" -and $WeeklyMessageEnabled -eq "True") {
        $Conflicts += "Multiple trigger features enabled: PendingRebootUptime and WeeklyMessage both active"
    }
    
    # Note: Notification app conflicts are handled in main script (CustomNotificationApp takes precedence)
    # No need to block detection for this - it's a configuration warning, not a blocking issue
    
    return $Conflicts
}

# Create Get-ToastConfig function
function Get-ToastConfig() {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ConfigPath
    )
    
    Write-Host "[ToastNotificationScript] Loading configuration file: $ConfigPath"

    if ($ConfigPath -match "^https?://") {
        Write-Host "[ToastNotificationScript] Config file is hosted online. Downloading from: $ConfigPath"
        try {
            $ConfigContent = Invoke-RestMethod -Uri $ConfigPath -Method Get -UseBasicParsing
            $Xml = [xml]$ConfigContent
            Write-Host "[ToastNotificationScript] Successfully loaded online config file"
            return $Xml
        }
        catch {
            $ErrorMessage = $_.Exception.Message
            Write-Host "[ToastNotificationScript] Failed to load online config file: $ErrorMessage"
            Exit 0
        }
    }
    else {
        Write-Host "[ToastNotificationScript] Config file is local or on file share: $ConfigPath"
        if (Test-Path -Path $ConfigPath) {
            try { 
                $Xml = [xml](Get-Content -Path $ConfigPath -Encoding UTF8)
                Write-Host "[ToastNotificationScript] Successfully loaded local config file"
                return $Xml
            }
            catch {
                $ErrorMessage = $_.Exception.Message
                Write-Host "[ToastNotificationScript] Failed to read local config file: $ErrorMessage"
                Exit 0
            }
        }
        else {
            Write-Host "[ToastNotificationScript] Config file not found at: $ConfigPath"
            Exit 0
        }
    }
}

try {
    # Load config using the same function as main script
    Write-Output "[ToastNotificationScript] Loading configuration..."
    $Xml = Get-ToastConfig -ConfigPath $Config
    
    # Check for configuration conflicts
    Write-Output "[ToastNotificationScript] Checking configuration for conflicts..."
    $ConfigConflicts = Test-ConfigConflicts -ConfigXml $Xml
    
    if ($ConfigConflicts.Count -gt 0) {
        Write-Output "[ToastNotificationScript] Configuration conflicts detected:"
        foreach ($Conflict in $ConfigConflicts) {
            Write-Output "[ToastNotificationScript] - $Conflict"
        }
        Write-Output "[ToastNotificationScript] No action needed due to configuration conflicts"
        exit 0
    }
    else {
        Write-Output "[ToastNotificationScript] Configuration validation passed"
    }
    
    # Initialize action needed flag
    $ActionNeeded = $false
    
    # Check PendingRebootUptime feature
    $UptimeEnabled = $Xml.Configuration.Feature | Where-Object {$_.Name -eq "PendingRebootUptime"} | Select-Object -ExpandProperty Enabled
    if ($UptimeEnabled -eq "True") {
        Write-Output "[ToastNotificationScript] Checking PendingRebootUptime feature..."
        
        # Get MaxUptimeDays from config
        $MaxUptimeDaysValue = $Xml.Configuration.Option | Where-Object {$_.Name -eq "MaxUptimeDays"} | Select-Object -ExpandProperty Value
        $MaxUptimeDays = [int]$MaxUptimeDaysValue
        
        # Check uptime using the same function as main script
        $UptimeDays = Get-DeviceUptime
        
        if ($UptimeDays -gt $MaxUptimeDays) {
            Write-Output "[ToastNotificationScript] PendingRebootUptime: Uptime threshold exceeded ($UptimeDays > $MaxUptimeDays days)"
            $ActionNeeded = $true
        }
        else {
            Write-Output "[ToastNotificationScript] PendingRebootUptime: Uptime within threshold ($UptimeDays <= $MaxUptimeDays days)"
        }
    }
    else {
        Write-Output "[ToastNotificationScript] PendingRebootUptime feature disabled in config"
    }
    
    # Check WeeklyMessage feature
    $WeeklyMessageEnabled = $Xml.Configuration.Feature | Where-Object {$_.Name -eq "WeeklyMessage"} | Select-Object -ExpandProperty Enabled
    if ($WeeklyMessageEnabled -eq "True") {
        Write-Output "[ToastNotificationScript] Checking WeeklyMessage feature..."
        
        # Get configuration values
        $TargetDay = $Xml.Configuration.Option | Where-Object {$_.Name -eq "WeeklyMessageDay"} | Select-Object -ExpandProperty Value
        $TargetHour = [int]($Xml.Configuration.Option | Where-Object {$_.Name -eq "WeeklyMessageHour"} | Select-Object -ExpandProperty Value)
        
        # Parse target days (support comma-separated numeric values)
        $TargetDayStrings = $TargetDay -split ',' | ForEach-Object { $_.Trim() }
        $TargetDays = @()
        $InvalidDays = @()
        
        foreach ($DayString in $TargetDayStrings) {
            if ($DayString -match '^\d+$') {
                $DayNumber = [int]$DayString
                if ($DayNumber -ge 1 -and $DayNumber -le 7) {
                    $TargetDays += $DayNumber
                } else {
                    $InvalidDays += $DayString
                }
            } else {
                $InvalidDays += $DayString
            }
        }
        
        # Report invalid day numbers
        if ($InvalidDays.Count -gt 0) {
            Write-Output "[ToastNotificationScript] WeeklyMessage: Invalid day numbers found: $($InvalidDays -join ', '). Valid range: 1-7 (1=Monday, 2=Tuesday, 3=Wednesday, 4=Thursday, 5=Friday, 6=Saturday, 7=Sunday)"
        }
        
        if ($TargetDays.Count -eq 0) {
            Write-Output "[ToastNotificationScript] WeeklyMessage: No valid target days configured - skipping"
        }
        else {
            $CurrentTime = Get-Date
            # Get numeric day of week (0=Sunday, 1=Monday, ..., 6=Saturday)
            $CurrentDayNumber = [int]$CurrentTime.DayOfWeek
            # Convert to ISO 8601 format (1=Monday, 7=Sunday) for consistency
            if ($CurrentDayNumber -eq 0) { $CurrentDayNumber = 7 } # Sunday: 0 -> 7
            
            $CurrentHour = $CurrentTime.Hour
            $CurrentMinute = $CurrentTime.Minute
            
            # Convert day numbers to names for logging (always English for consistency)
            $DayNames = @('', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday')
            $CurrentDayName = $DayNames[$CurrentDayNumber]
            $TargetDayNames = $TargetDays | ForEach-Object { $DayNames[$_] }
            
            # Check if current day is in target days
            if ($TargetDays -contains $CurrentDayNumber) {
                # Check hour condition
                if ($TargetHour -eq -1) {
                    # Hour = -1 means "any time during the target day"
                    Write-Output "[ToastNotificationScript] WeeklyMessage: Trigger time reached: $CurrentDayName (day $CurrentDayNumber) at $CurrentHour`:$($CurrentMinute.ToString('00')) - any hour (configured days: $($TargetDayNames -join ', '))"
                    $ActionNeeded = $true
                }
                elseif ($CurrentHour -eq $TargetHour) {
                    # Normal hour-specific behavior
                    Write-Output "[ToastNotificationScript] WeeklyMessage: Trigger time reached: $CurrentDayName (day $CurrentDayNumber) at $TargetHour`:$($CurrentMinute.ToString('00')) (configured days: $($TargetDayNames -join ', '))"
                    $ActionNeeded = $true
                }
                else {
                    Write-Output "[ToastNotificationScript] WeeklyMessage: Correct day but wrong hour (current: $CurrentDayName (day $CurrentDayNumber) at $CurrentHour`:$($CurrentMinute.ToString('00')), target: $($TargetDayNames -join ', ') at $TargetHour`:00)"
                }
            }
            else {
                $HourDisplay = if ($TargetHour -eq -1) { "any hour" } else { "$TargetHour`:00" }
                Write-Output "[ToastNotificationScript] WeeklyMessage: Not trigger time (current: $CurrentDayName (day $CurrentDayNumber) at $CurrentHour`:$($CurrentMinute.ToString('00')), target days: $($TargetDayNames -join ', ') at $HourDisplay)"
            }
        }
    }
    else {
        Write-Output "[ToastNotificationScript] WeeklyMessage feature disabled in config"
    }
    
    # Add future detection methods here...
    # Example:
    # $SomeOtherFeatureEnabled = $Xml.Configuration.Feature | Where-Object {$_.Name -eq "SomeOtherFeature"} | Select-Object -ExpandProperty Enabled
    # if ($SomeOtherFeatureEnabled -eq "True") {
    #     Write-Output "[ToastNotificationScript] Checking SomeOtherFeature..."
    #     # Detection logic here
    #     if ($someCondition) {
    #         $RemediationNeeded = $true
    #     }
    # }
    
    # Final decision
    if ($ActionNeeded) {
        Write-Output "[ToastNotificationScript] Action needed - one or more conditions met"
        exit 1
    }
    else {
        Write-Output "[ToastNotificationScript] No action needed - all conditions within thresholds"
        exit 0
    }
}
catch {
    Write-Output "[ToastNotificationScript] Error: $($_.Exception.Message)"
    exit 0
}