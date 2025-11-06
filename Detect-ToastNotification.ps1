<#
.SYNOPSIS
    Detect-ToastNotification.ps1 - Detection Script for Toast Notification Script for Microsoft Intune

.DESCRIPTION
    This PowerShell script serves as the detection component for Toast Notification Script in Microsoft Intune.
    It evaluates various system conditions and configuration settings to determine whether toast notifications should be displayed
    to end users, working in conjunction with Remediate-ToastNotification.ps1 to provide intelligent notification delivery.

    Detection Capabilities:
    • Pending Reboot Detection: Monitors system uptime against configurable thresholds
    • Weekly Message Scheduling: Evaluates day/hour triggers for routine notifications using international-compatible numeric format
    • Configuration Validation: Checks XML configuration integrity and feature enablement
    • Conflict Detection: Identifies conflicting settings that could prevent proper notification delivery
    • System Compatibility: Validates Windows version and environment requirements

    International Compatibility:
    • Uses ISO 8601 numeric day format (1=Monday through 7=Sunday) for culture-independent operation
    • Eliminates localization issues found in earlier versions
    • Supports all Windows language installations without modification
    • Consistent behavior across international deployments

    Detection Logic:
    The script evaluates multiple conditions based on XML configuration:
    1. Global Toast feature enablement check
    2. Individual feature validation (WeeklyMessage, PendingRebootUptime)
    3. System state evaluation (uptime, day/hour matching)
    4. Configuration conflict detection
    5. Exit code determination for Intune reporting

.PARAMETER Config
    Specifies the path or URL to the XML configuration file. Must match the configuration used by the Toast Notification Script.
    Default: "https://krpublicfiles.blob.core.windows.net/toastnotification/config-toast.xml"

.EXAMPLE
    .\Detect-ToastNotification.ps1
    Performs detection using the default configuration file with standard output.

.EXAMPLE
    .\Detect-ToastNotification.ps1 -Config "https://company.blob.core.windows.net/config/custom-toast.xml"
    Performs detection using a custom configuration file hosted online.

.EXAMPLE
    $LASTEXITCODE = .\Detect-ToastNotification.ps1; if ($LASTEXITCODE -eq 1) { Write-Host "Toast notification needed" }
    Demonstrates exit code evaluation for conditional processing.

.INPUTS
    None. This script does not accept pipeline input.

.OUTPUTS
    System.Int32
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
    • Internet connectivity for online configuration files
    • Same configuration file as Toast Notification Script
    
    Intune Deployment Guidelines:
    • Deploy as detection script in Microsoft Intune
    • Pair with Remediate-ToastNotification.ps1 as the action script
    • Configure appropriate detection schedule (e.g., hourly, daily)
    • Ensure consistent configuration file usage between detection and action scripts
    • Monitor detection results through Intune reporting dashboard

    Detection Strategy:
    • Fail-safe approach: defaults to "no action needed" on errors
    • Comprehensive logging for troubleshooting detection issues
    • Validates configuration before evaluating conditions
    • Handles network connectivity issues gracefully
    • Provides clear exit reasoning for administrative review

    Performance Considerations:
    • Lightweight operation suitable for frequent execution
    • Minimal system impact during detection evaluation
    • Efficient XML parsing and condition evaluation
    • Quick exit on configuration errors or disabled features

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