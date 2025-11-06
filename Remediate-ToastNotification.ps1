<#
.SYNOPSIS
    Remediate-ToastNotification.ps1 - Toast Notification Script for Microsoft Intune

.DESCRIPTION
    Delivers native Windows toast notifications to end users through Microsoft Intune.
    This is the Toast Notification Script, completely rewritten for Microsoft Intune.

    Key Features:
    • Weekly reminders with flexible scheduling (multiple days, any hour support)
    • Pending reboot notifications based on configurable uptime thresholds
    • Personalized greetings with dynamic time-based salutations
    • Multi-level logging with rotation and error handling
    • International compatibility with culture-independent operation
    • PowerShell Constrained Language Mode compatibility

.PARAMETER Config
    Path or URL to the XML configuration file.
    Default: "https://toast.imab.dk/config-toast-pendingreboot.xml"

.EXAMPLE
    .\Remediate-ToastNotification.ps1

.OUTPUTS
    Returns exit codes for Microsoft Intune reporting:
    • 0: Success - Toast notification displayed or conditions not met (no action needed)
    • 1: Configuration error or critical failure

.NOTES
    Script Name    : Remediate-ToastNotification.ps1
    Version        : 3.0.0
    Author         : Martin Bengtsson, Rewritten for Microsoft Intune
    Created        : November 2025
    Updated        : November 2025

    Requirements:
    â€¢ Windows 10 version 1709 or later / Windows 11
    â€¢ PowerShell 5.1 or later
    â€¢ Microsoft Intune managed device
    â€¢ User context execution (not SYSTEM)
    â€¢ Internet connectivity for online configuration files

    Intune Deployment:
    â€¢ Deploy with detection script: Detect-ToastNotification.ps1
    â€¢ Configure appropriate schedule based on notification requirements
    â€¢ Ensure proper user assignment and targeting

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
function Write-Log() {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias("LogContent")]
        [string]$Message,
        [Parameter(Mandatory=$false)]
        [Alias('LogPath')]
        [string]$Path = "$env:APPDATA\ToastNotificationScript\Remediate-ToastNotification.log",
        [Parameter(Mandatory=$false)]
        [ValidateSet("Error","Warn","Info","Debug")]
        [string]$Level = "Info",
        [Parameter(Mandatory=$false)]
        [switch]$NoConsoleOutput,
        [Parameter(Mandatory=$false)]
        [switch]$IncludeIMEOutput
    )

    Process {
        try {
            # Ensure log directory exists
            $LogDirectory = Split-Path -Path $Path -Parent
            if (-NOT(Test-Path -Path $LogDirectory)) {
                try {
                    New-Item -Path $LogDirectory -ItemType Directory -Force -ErrorAction Stop | Out-Null
                }
                catch {
                    Write-Warning "Failed to create log directory: $LogDirectory. Error: $_"
                    return
                }
            }

            # Check log file size and handle rotation
            $LogSize = 0
            $MaxLogSize = 5 # MB

            if (Test-Path -Path $Path) {
                try {
                    $LogSize = (Get-Item -Path $Path -ErrorAction Stop).Length / 1MB
                }
                catch {
                    Write-Warning "Could not check log file size: $_"
                }
            }

            # Rotate log if too large
            if ($LogSize -gt $MaxLogSize) {
                try {
                    $BackupPath = $Path -replace "\.log$", "_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
                    Move-Item -Path $Path -Destination $BackupPath -ErrorAction Stop
                }
                catch {
                    Write-Warning "Failed to rotate log file: $_"
                    # If rotation fails, delete the old log
                    try {
                        Remove-Item -Path $Path -Force -ErrorAction Stop
                    }
                    catch {
                        Write-Warning "Failed to delete old log file: $_"
                        return
                    }
                }
            }

            # Format timestamp and level
            $FormattedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            $ProcessId = $PID
            $Username = [Environment]::UserName

            # Determine level text
            switch ($Level) {
                'Error' { $LevelText = 'ERROR' }
                'Warn'  { $LevelText = 'WARN ' }
                'Info'  { $LevelText = 'INFO ' }
                'Debug' { $LevelText = 'DEBUG' }
            }

            # Create log entry
            $LogEntry = "$FormattedDate [$LevelText] [PID:$ProcessId] [User:$Username] $Message"

            # Write to log file first (most important)
            try {
                $LogEntry | Out-File -FilePath $Path -Append -ErrorAction Stop
            }
            catch {
                Write-Warning "Failed to write to log file: $_"
                # Fallback: try to write to Windows Event Log
                try {
                    Write-EventLog -LogName Application -Source "ToastNotificationScript" -EventId 1001 -EntryType Information -Message $Message -ErrorAction SilentlyContinue
                }
                catch {
                    # Silent failure for event log as it's just a fallback
                }
            }

            # Write to console (optional)
            if (-not $NoConsoleOutput) {
                # Set VerbosePreference temporarily to ensure output
                $OriginalVerbosePreference = $VerbosePreference
                try {
                    switch ($Level) {
                        'Error' {
                            Write-Error $Message -ErrorAction SilentlyContinue
                        }
                        'Warn'  {
                            Write-Warning $Message
                        }
                        'Info'  {
                            $VerbosePreference = 'Continue'
                            Write-Verbose $Message
                        }
                        'Debug' {
                            if ($DebugPreference -ne 'SilentlyContinue') {
                                Write-Debug $Message
                            }
                        }
                    }
                }
                finally {
                    $VerbosePreference = $OriginalVerbosePreference
                }
            }

            # Add IME logging if requested
            if ($IncludeIMEOutput) {
                Write-Output "[ToastNotificationScript] $Message"
            }
        }
        catch {
            Write-Warning "Unexpected error in Write-Log function: $_"
        }
    }
}

# Create Test-WeeklyMessageTrigger function
function Test-WeeklyMessageTrigger() {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$TargetDay,  # Now accepts comma-separated numeric values (1=Monday, 7=Sunday)
        [Parameter(Mandatory=$true)]
        [int]$TargetHour
    )

    $CurrentTime = Get-Date
    # Get numeric day of week (0=Sunday, 1=Monday, ..., 6=Saturday)
    $CurrentDayNumber = [int]$CurrentTime.DayOfWeek
    # Convert to ISO 8601 format (1=Monday, 7=Sunday) for consistency
    if ($CurrentDayNumber -eq 0) { $CurrentDayNumber = 7 } # Sunday: 0 -> 7

    $CurrentHour = $CurrentTime.Hour
    $CurrentMinute = $CurrentTime.Minute

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
        Write-Log -Level Warn -Message "WeeklyMessage: Invalid day numbers found: $($InvalidDays -join ', '). Valid range: 1-7 (1=Monday, 2=Tuesday, 3=Wednesday, 4=Thursday, 5=Friday, 6=Saturday, 7=Sunday)"
    }

    # Skip if no valid days remain
    if ($TargetDays.Count -eq 0) {
        Write-Log -Level Warn -Message "WeeklyMessage: No valid target days configured - skipping trigger check"
        return $false
    }

    # Convert day numbers to names for logging (always English for consistency)
    $DayNames = @('', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday')
    $CurrentDayName = $DayNames[$CurrentDayNumber]
    $TargetDayNames = $TargetDays | ForEach-Object { $DayNames[$_] }

    # Check if current day is in target days
    if ($TargetDays -contains $CurrentDayNumber) {
        # Check hour condition
        if ($TargetHour -eq -1) {
            # Hour = -1 means "any time during the target day"
            Write-Log -Message "WeeklyMessage trigger conditions met: $CurrentDayName (day $CurrentDayNumber) at $CurrentHour`:$($CurrentMinute.ToString('00')) - any hour (configured days: $($TargetDayNames -join ', '))"
            return $true
        }
        elseif ($CurrentHour -eq $TargetHour) {
            # Normal hour-specific behavior
            Write-Log -Message "WeeklyMessage trigger conditions met: $CurrentDayName (day $CurrentDayNumber) at $TargetHour`:$($CurrentMinute.ToString('00')) (configured days: $($TargetDayNames -join ', '))"
            return $true
        }
        else {
            Write-Log -Message "WeeklyMessage: Correct day but wrong hour (current: $CurrentDayName (day $CurrentDayNumber) at $CurrentHour`:$($CurrentMinute.ToString('00')), target: $($TargetDayNames -join ', ') at $TargetHour`:00)"
            return $false
        }
    }
    else {
        $HourDisplay = if ($TargetHour -eq -1) { "any hour" } else { "$TargetHour`:00" }
        Write-Log -Message "WeeklyMessage: Not trigger time (current: $CurrentDayName (day $CurrentDayNumber) at $CurrentHour`:$($CurrentMinute.ToString('00')), target days: $($TargetDayNames -join ', ') at $HourDisplay)"
        return $false
    }
}

# Create Get Device Uptime function
function Get-DeviceUptime() {
    Write-Log -Message "Executing Get-DeviceUptime function"
    $OS = Get-CimInstance Win32_OperatingSystem
    $Uptime = (Get-Date) - ($OS.LastBootUpTime)
    $Uptime.Days
}

# Create Get-WindowsVersion function
# This determines if the script is running on a supported Windows version
function Get-WindowsVersion() {
    Write-Log -Message "Executing Get-WindowsVersion function"

    try {
        # Get OS information using CIM
        $OS = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop

        $OSVersion = $OS.Version
        $ProductType = $OS.ProductType
        $OSCaption = $OS.Caption
        $BuildNumber = $OS.BuildNumber

        Write-Log -Message "Detected OS: $OSCaption (Version: $OSVersion, Build: $BuildNumber)"

        # Only supports workstations (ProductType = 1)
        if ($ProductType -ne 1) {
            Write-Log -Level Error -Message "Unsupported OS type detected - only Windows 10/11 workstations are supported"
            return $false
        }

        # Check if Windows 10 or later (version 10.0.x)
        if ($OSVersion -like "10.0.*") {

            # Determine Windows version based on build number
            if ($BuildNumber -ge 22000) {
                $WindowsVersion = "Windows 11"
                $MinBuildMet = $true
            } elseif ($BuildNumber -ge 10240) {
                $WindowsVersion = "Windows 10"
                $MinBuildMet = $true
            } else {
                $WindowsVersion = "Windows 10 (Unsupported Build)"
                $MinBuildMet = $false
            }

            if ($MinBuildMet) {
                Write-Log -Message "Supported $WindowsVersion workstation detected (Build: $BuildNumber)"
                return $true
            } else {
                Write-Log -Level Error -Message "Windows 10 build too old (Build: $BuildNumber) - minimum build 10240 required"
                return $false
            }

        } else {
            # Pre-Windows 10 versions
            Write-Log -Level Error -Message "Unsupported Windows version: $OSCaption (Version: $OSVersion)"
            return $false
        }

    }
    catch {
        Write-Log -Level Error -Message "Failed to retrieve Windows version information: $_"
        return $false
    }
}

# Create Get Given Name function
function Get-GivenName() {
    Write-Log -Message "Executing Get-GivenName function"

    # Try to get given name from environment variables first
    $GivenName = $null

    # Method 1: Try from Windows environment
    try {
        $UserInfo = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object UserName
        if ($UserInfo.UserName -and $UserInfo.UserName.Contains('\')) {
            $Username = $UserInfo.UserName.Split('\')[1]
            Write-Log -Message "Found username from Win32_ComputerSystem: $Username"
        }
    }
    catch {
        Write-Log -Level Warn -Message "Could not retrieve user info from Win32_ComputerSystem: $_"
    }

    # Method 2: Try from registry (most reliable approach)
    if ([string]::IsNullOrEmpty($GivenName)) {
        Write-Log -Message "Attempting to find given name from registry"
        $RegKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI"
        try {
            $LogonUIInfo = Get-ItemProperty -Path $RegKey -ErrorAction SilentlyContinue
            if ($LogonUIInfo.LastLoggedOnDisplayName) {
                $LoggedOnUserDisplayName = $LogonUIInfo.LastLoggedOnDisplayName
                if (-NOT[string]::IsNullOrEmpty($LoggedOnUserDisplayName)) {
                    $DisplayName = $LoggedOnUserDisplayName.Split(" ")
                    $GivenName = $DisplayName[0]
                    Write-Log -Message "Successfully found given name from registry: $GivenName"
                }
            }
        }
        catch {
            Write-Log -Level Warn -Message "Could not access LogonUI registry: $_"
        }
    }
    # Method 3: Try from user profile registry
    if ([string]::IsNullOrEmpty($GivenName)) {
        try {
            $UserRegKey = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
            $UserInfo = Get-ItemProperty -Path $UserRegKey -Name "Logon User Name" -ErrorAction SilentlyContinue
            if ($UserInfo) {
                $GivenName = $UserInfo."Logon User Name"
                Write-Log -Message "Successfully found given name from user registry: $GivenName"
            }
        }
        catch {
            Write-Log -Level Warn -Message "Could not access user registry: $_"
        }
    }
    # Fallback to username, then to generic placeholder
    if ([string]::IsNullOrEmpty($GivenName)) {
        try {
            $GivenName = [Environment]::UserName
            if (-NOT[string]::IsNullOrEmpty($GivenName)) {
                Write-Log -Message "Using username as fallback: $GivenName"
            } else {
                $GivenName = "there"
                Write-Log -Message "Using generic fallback: $GivenName"
            }
        }
        catch {
            $GivenName = "there"
            Write-Log -Message "Using generic fallback due to error: $GivenName"
        }
    }
    return $GivenName
}

# Create Windows Push Notification function
# This tests if toast notifications are enabled in Windows
function Test-WindowsPushNotificationsEnabled() {
    Write-Log -Message "Executing Test-WindowsPushNotificationsEnabled function"

    try {
        $ToastEnabledKey = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -ErrorAction SilentlyContinue

        if ($ToastEnabledKey -and $ToastEnabledKey.ToastEnabled -eq 1) {
            Write-Log -Message "Toast notifications are enabled for logged on user"
            return $true
        }
        elseif ($ToastEnabledKey -and $ToastEnabledKey.ToastEnabled -eq 0) {
            Write-Log -Level Warn -Message "Toast notifications are disabled for logged on user"
            return $false
        }
        else {
            Write-Log -Level Warn -Message "Cannot determine toast notification status - registry key not found"
            return $false
        }
    }
    catch {
        Write-Log -Level Error -Message "Failed to check toast notification status: $_"
        return $false
    }
}

# Create Enable-WindowsPushNotifications function
# This attempts to re-enable toast notifications if disabled
function Enable-WindowsPushNotifications() {
    Write-Log -Message "Attempting to enable toast notifications for the logged on user"

    try {
        $ToastEnabledKeyPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications"

        # Ensure the registry path exists
        if (-not (Test-Path $ToastEnabledKeyPath)) {
            New-Item -Path $ToastEnabledKeyPath -Force | Out-Null
            Write-Log -Message "Successfully created PushNotifications registry path"
        }

        # Enable toast notifications
        Set-ItemProperty -Path $ToastEnabledKeyPath -Name "ToastEnabled" -Value 1 -Force
        Write-Log -Message "Successfully set ToastEnabled registry value to 1"

        # Try to restart the notification service (best effort)
        try {
            $NotificationService = Get-Service -Name "WpnUserService*" -ErrorAction SilentlyContinue
            if ($NotificationService) {
                $NotificationService | Restart-Service -Force -ErrorAction SilentlyContinue
                Write-Log -Message "Successfully restarted Windows Push Notification service"
            }
        }
        catch {
            Write-Log -Level Warn -Message "Could not restart notification service: $_"
        }

        Write-Log -Message "Successfully enabled toast notifications for the logged on user"
        return $true
    }
    catch {
        Write-Log -Level Error -Message "Failed to enable toast notifications: $_"
        return $false
    }
}

# Create Get-ToastConfig function
function Get-ToastConfig() {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ConfigPath
    )

    Write-Log -Message "Loading configuration file: $ConfigPath"

    if ($ConfigPath -match "^https?://") {
        Write-Log -Message "Config file is hosted online. Downloading from: $ConfigPath"
        try {
            # Use Invoke-RestMethod for CLM compatibility and single request
            $ConfigContent = Invoke-RestMethod -Uri $ConfigPath -Method Get -UseBasicParsing
            $Xml = [xml]$ConfigContent
            Write-Log -Message "Successfully loaded online config file: $ConfigPath"
            return $Xml
        }
        catch {
            $ErrorMessage = $_.Exception.Message
            Write-Log -Message "Failed to load online config file: $ConfigPath" -Level Error -IncludeIMEOutput
            Write-Log -Message "Error details: $ErrorMessage" -Level Error
            Exit 0
        }
    }
    else {
        Write-Log -Message "Config file is local or on file share: $ConfigPath"
        if (Test-Path -Path $ConfigPath) {
            try {
                $Xml = [xml](Get-Content -Path $ConfigPath -Encoding UTF8)
                Write-Log -Message "Successfully loaded local config file: $ConfigPath"
                return $Xml
            }
            catch {
                $ErrorMessage = $_.Exception.Message
                Write-Log -Message "Failed to read local config file: $ConfigPath" -Level Error -IncludeIMEOutput
                Write-Log -Message "Error details: $ErrorMessage" -Level Error
                Exit 0
            }
        }
        else {
            Write-Log -Level Error -Message "Config file not found at: $ConfigPath" -IncludeIMEOutput
            Exit 0
        }
    }
}

# Function to check for configuration conflicts
function Test-ConfigConflicts() {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [xml]$ConfigXml
    )

    Write-Log -Message "Executing Test-ConfigConflicts function"

    $Conflicts = @()
    $Warnings = @()

    # Check if Toast feature is globally disabled (should be first check)
    $ToastEnabled = ($ConfigXml.Configuration.Feature | Where-Object {$_.Name -eq "Toast"}).Enabled
    if ($ToastEnabled -ne "True") {
        $Conflicts += "Toast feature is disabled in configuration (Toast Enabled = '$ToastEnabled') - no notifications can be displayed"
        # Log findings and return early if Toast is disabled
        Write-Log -Level Error -Message "Configuration conflicts detected:"
        Write-Log -Level Error -Message "  - Toast feature is disabled in configuration"
        return @{
            Conflicts = $Conflicts
            Warnings = $Warnings
            HasConflicts = $true
            HasWarnings = $false
        }
    }

    # Only check other conflicts if Toast is enabled
    # Check for multiple trigger features enabled simultaneously
    $PendingRebootUptimeEnabled = ($ConfigXml.Configuration.Feature | Where-Object {$_.Name -eq "PendingRebootUptime"}).Enabled
    $WeeklyMessageEnabled = ($ConfigXml.Configuration.Feature | Where-Object {$_.Name -eq "WeeklyMessage"}).Enabled

    if ($PendingRebootUptimeEnabled -eq "True" -and $WeeklyMessageEnabled -eq "True") {
        $Conflicts += "Multiple trigger features enabled: PendingRebootUptime and WeeklyMessage both active - only one trigger feature should be enabled at a time"
    }

    # Check for notification app conflicts - simplified since UsePowershellApp has been removed
    # Note: UsePowershellApp option has been removed. PowerShell app is now the automatic fallback when CustomNotificationApp is disabled.

    # Check for button logic conflicts
    $SnoozeEnabled = ($ConfigXml.Configuration.Option | Where-Object {$_.Name -eq "SnoozeButton"}).Enabled
    $ActionButton1Enabled = ($ConfigXml.Configuration.Option | Where-Object {$_.Name -eq "ActionButton1"}).Enabled
    $ActionButton2Enabled = ($ConfigXml.Configuration.Option | Where-Object {$_.Name -eq "ActionButton2"}).Enabled
    $DismissEnabled = ($ConfigXml.Configuration.Option | Where-Object {$_.Name -eq "DismissButton"}).Enabled

    if ($SnoozeEnabled -eq "True") {
        if ($ActionButton1Enabled -eq "False" -and $ActionButton2Enabled -eq "False") {
            $Warnings += "SnoozeButton is enabled but both ActionButtons are disabled. SnoozeButton will force ActionButton to be enabled."
        }
        if ($DismissEnabled -eq "False") {
            $Warnings += "SnoozeButton is enabled but DismissButton is disabled. SnoozeButton will force DismissButton to be enabled."
        }
    }

    # Check scenario vs feature compatibility
    $Scenario = ($ConfigXml.Configuration.Option | Where-Object {$_.Name -eq "Scenario"}).Type

    if ($Scenario -eq "alarm" -and $SnoozeEnabled -ne "True") {
        $Warnings += "Scenario is set to 'alarm' but SnoozeButton is disabled. Alarm scenarios typically work better with snooze functionality."
    }

    if ($Scenario -eq "long" -and $ActionButton1Enabled -ne "True" -and $ActionButton2Enabled -ne "True") {
        $Warnings += "Scenario is set to 'long' but no ActionButtons are enabled. Long scenarios typically include action buttons for user interaction."
    }

    # Check uptime threshold validity
    if ($PendingRebootUptimeEnabled -eq "True") {
        $MaxUptimeDays = ($ConfigXml.Configuration.Option | Where-Object {$_.Name -eq "MaxUptimeDays"}).Value
        if ($MaxUptimeDays -and [int]$MaxUptimeDays -lt 0) {
            $Warnings += "MaxUptimeDays is set to negative value ($MaxUptimeDays). This may cause unexpected behavior."
        }
    }

    # Log findings
    if ($Conflicts.Count -gt 0) {
        Write-Log -Level Error -Message "Configuration conflicts detected:"
        foreach ($Conflict in $Conflicts) {
            Write-Log -Level Error -Message "  - $Conflict"
        }
    }

    if ($Warnings.Count -gt 0) {
        Write-Log -Level Warn -Message "Configuration warnings detected:"
        foreach ($Warning in $Warnings) {
            Write-Log -Level Warn -Message "  - $Warning"
        }
    }

    if ($Conflicts.Count -eq 0 -and $Warnings.Count -eq 0) {
        Write-Log -Message "Configuration validation passed - no conflicts detected"
    }

    return @{
        Conflicts = $Conflicts
        Warnings = $Warnings
        HasConflicts = ($Conflicts.Count -gt 0)
        HasWarnings = ($Warnings.Count -gt 0)
    }
}

# Create New-ToastXml function
function New-ToastXml() {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [bool]$IncludeActionButton1 = $false,
        [Parameter(Mandatory=$false)]
        [bool]$IncludeActionButton2 = $false,
        [Parameter(Mandatory=$false)]
        [bool]$IncludeDismissButton = $false,
        [Parameter(Mandatory=$false)]
        [bool]$IncludeSnoozeButton = $false,
        [Parameter(Mandatory=$false)]
        [bool]$IncludeUptimeInfo = $false,
        [Parameter(Mandatory=$false)]
        [int]$UptimeDays = 0,
        [Parameter(Mandatory=$false)]
        [bool]$IsWeeklyMessage = $false
    )

    # Build the common visual structure
    $VisualXml = @"
    <visual>
    <binding template="ToastGeneric">
        <image placement="hero" src="$HeroImage"/>
        <image id="1" placement="appLogoOverride" hint-crop="circle" src="$LogoImage"/>
        <text placement="attribution">$AttributionText</text>
        <text>$HeaderText</text>
        <group>
            <subgroup>
                <text hint-style="title" hint-wrap="true">$(if ($IsWeeklyMessage -and -NOT[string]::IsNullOrEmpty($WeeklyMessageTitleText)) { $WeeklyMessageTitleText } else { $TitleText })</text>
            </subgroup>
        </group>
        <group>
            <subgroup>
                <text hint-style="body" hint-wrap="true">$(if ($IsWeeklyMessage -and -NOT[string]::IsNullOrEmpty($WeeklyMessageBodyText)) { $WeeklyMessageBodyText } else { $BodyText1 })</text>
            </subgroup>
        </group>
        <group>
            <subgroup>
                <text hint-style="body" hint-wrap="true">$(if ($IsWeeklyMessage) { "" } else { $BodyText2 })</text>
            </subgroup>
        </group>
"@

    # Add uptime information if requested
    if ($IncludeUptimeInfo) {
        $VisualXml += @"
        <group>
            <subgroup>
                <text hint-style="body" hint-wrap="true" >$PendingRebootUptimeTextValue</text>
            </subgroup>
        </group>
        <group>
            <subgroup>
                <text hint-style="base" hint-align="left">$ComputerUptimeText $UptimeDays $ComputerUptimeDaysText</text>
            </subgroup>
        </group>
"@
    }

    # Close the visual section
    $VisualXml += @"
    </binding>
    </visual>
"@

    # Build the actions section dynamically
    $ActionsContent = ""

    if ($IncludeSnoozeButton) {
        # Snooze button takes priority and includes specific input controls
        $ActionsContent = @"
        <input id="snoozeTime" type="selection" title="$SnoozeText" defaultInput="15">
            <selection id="15" content="15 $MinutesText"/>
            <selection id="30" content="30 $MinutesText"/>
            <selection id="60" content="1 $HourText"/>
            <selection id="240" content="4 $HoursText"/>
            <selection id="480" content="8 $HoursText"/>
        </input>
        <action activationType="protocol" arguments="$Action1" content="$ActionButton1Content" />
        <action activationType="system" arguments="snooze" hint-inputId="snoozeTime" content="$SnoozeButtonContent"/>
        <action activationType="system" arguments="dismiss" content="$DismissButtonContent"/>
"@
    } else {
        # Build standard actions
        if ($IncludeActionButton1) {
            $ActionsContent += "        <action activationType=`"protocol`" arguments=`"$Action1`" content=`"$ActionButton1Content`" />`n"
        }
        if ($IncludeActionButton2) {
            $ActionsContent += "        <action activationType=`"protocol`" arguments=`"$Action2`" content=`"$ActionButton2Content`" />`n"
        }
        if ($IncludeDismissButton) {
            $ActionsContent += "        <action activationType=`"system`" arguments=`"dismiss`" content=`"$DismissButtonContent`"/>`n"
        }
    }

    # Combine everything into the complete toast XML
    $CompleteXml = @"
<toast scenario="$Scenario">
$VisualXml
    <actions>
$ActionsContent
    </actions>
</toast>
"@

    return [xml]$CompleteXml
}

# Create Get-ToastImage function
function Get-ToastImage() {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ImageUrl,
        [Parameter(Mandatory=$true)]
        [string]$LocalPath,
        [Parameter(Mandatory=$true)]
        [string]$ImageType
    )

    Write-Log -Message "Toast$ImageType appears to be hosted online. Downloading from: $ImageUrl"

    try {
        Invoke-WebRequest -Uri $ImageUrl -OutFile $LocalPath -UseBasicParsing
        Write-Log -Message "Successfully downloaded $ImageType from $ImageUrl to $LocalPath"
        return $LocalPath
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        Write-Log -Level Error -Message "Failed to download $ImageType from $ImageUrl. Error: $ErrorMessage"
        return $null
    }
}

# Create Show-ToastNotification function
function Show-ToastNotification() {
    try {
        # Determine which app to use for the notification
        if ($CustomAppEnabled -eq "True") {
            $App = "Toast.Custom.App"
            Write-Log -Message "Using custom notification app: $App"
            
            # Setup custom app registry entries
            $RegPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings"
            if (-NOT(Test-Path -Path "$RegPath\$App")) {
                New-Item -Path "$RegPath\$App" -Force | Out-Null
                New-ItemProperty -Path "$RegPath\$App" -Name "ShowInActionCenter" -Value 0 -PropertyType "DWORD" | Out-Null
                New-ItemProperty -Path "$RegPath\$App" -Name "Enabled" -Value 1 -PropertyType "DWORD" -Force | Out-Null
                New-ItemProperty -Path "$RegPath\$App" -Name "SoundFile" -PropertyType "STRING" -Force | Out-Null
            }
            # Ensure custom app is enabled
            if ((Get-ItemProperty -Path "$RegPath\$App" -Name "Enabled" -ErrorAction SilentlyContinue).Enabled -ne "1") {
                New-ItemProperty -Path "$RegPath\$App" -Name "Enabled" -Value 1 -PropertyType "DWORD" -Force | Out-Null
            }
        } else {
            $App = "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe"
            Write-Log -Message "Using PowerShell app as fallback: $App"
            
            # Setup PowerShell app registry entries
            $RegPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings"
            if (-NOT(Test-Path -Path "$RegPath\$App")) {
                New-Item -Path "$RegPath\$App" -Force | Out-Null
                New-ItemProperty -Path "$RegPath\$App" -Name "ShowInActionCenter" -Value 1 -PropertyType "DWORD" | Out-Null
                New-ItemProperty -Path "$RegPath\$App" -Name "Enabled" -Value 1 -PropertyType "DWORD" -Force | Out-Null
                New-ItemProperty -Path "$RegPath\$App" -Name "SoundFile" -PropertyType "STRING" -Force | Out-Null
            }
            # Ensure PowerShell app is enabled
            if ((Get-ItemProperty -Path "$RegPath\$App" -Name "Enabled" -ErrorAction SilentlyContinue).Enabled -ne "1") {
                New-ItemProperty -Path "$RegPath\$App" -Name "Enabled" -Value 1 -PropertyType "DWORD" -Force | Out-Null
            }
        }

        # Load WinRT assemblies for toast notifications
        [void][Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
        [void][Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime]
        # Load the notification into the required format
        $ToastXml = New-Object -TypeName Windows.Data.Xml.Dom.XmlDocument
        $ToastXml.LoadXml($Toast.OuterXml)
        # Display the toast notification
        [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($App).Show($ToastXml)
        Write-Log -Message "Successfully displayed toast notification" -IncludeIMEOutput
        # Saving time stamp of when toast notification was run into registry
        Save-NotificationLastRunTime
        Exit 0
    }
    catch {
        Write-Log -Message "Failed to display toast notification" -Level Error -IncludeIMEOutput
        Write-Log -Message "Error details: $_" -Level Error
        Write-Log -Message "Make sure the script is running as the logged on user" -Level Error
        Exit 1
    }
}
# Create Register-NotificationApp function
function Register-CustomNotificationApp($fAppID,$fAppDisplayName) {
    Write-Log -Message "Executing Register-CustomNotificationApp function"
    $AppID = $fAppID
    $AppDisplayName = $fAppDisplayName
    # This removes the option to disable to toast notification
    [int]$ShowInSettings = 0
    # Adds an icon next to the display name of the notifyhing app
    [int]$IconBackgroundColor = 0
    $IconUri = "%SystemRoot%\ImmersiveControlPanel\images\logo.png"
    # Moved this into HKCU, in order to modify this directly from the toast notification running in user context
    $AppRegPath = "HKCU:\Software\Classes\AppUserModelId"
    $RegPath = "$AppRegPath\$AppID"
    try {
        if (-NOT(Test-Path $RegPath)) {
            New-Item -Path $AppRegPath -Name $AppID -Force | Out-Null
        }
        $DisplayName = Get-ItemProperty -Path $RegPath -Name DisplayName -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DisplayName -ErrorAction SilentlyContinue
        if ($DisplayName -ne $AppDisplayName) {
            New-ItemProperty -Path $RegPath -Name DisplayName -Value $AppDisplayName -PropertyType String -Force | Out-Null
        }
        $ShowInSettingsValue = Get-ItemProperty -Path $RegPath -Name ShowInSettings -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ShowInSettings -ErrorAction SilentlyContinue
        if ($ShowInSettingsValue -ne $ShowInSettings) {
            New-ItemProperty -Path $RegPath -Name ShowInSettings -Value $ShowInSettings -PropertyType DWORD -Force | Out-Null
        }
        $IconUriValue = Get-ItemProperty -Path $RegPath -Name IconUri -ErrorAction SilentlyContinue | Select-Object -ExpandProperty IconUri -ErrorAction SilentlyContinue
        if ($IconUriValue -ne $IconUri) {
            New-ItemProperty -Path $RegPath -Name IconUri -Value $IconUri -PropertyType ExpandString -Force | Out-Null
        }
        $IconBackgroundColorValue = Get-ItemProperty -Path $RegPath -Name IconBackgroundColor -ErrorAction SilentlyContinue | Select-Object -ExpandProperty IconBackgroundColor -ErrorAction SilentlyContinue
        if ($IconBackgroundColorValue -ne $IconBackgroundColor) {
            New-ItemProperty -Path $RegPath -Name IconBackgroundColor -Value $IconBackgroundColor -PropertyType ExpandString -Force | Out-Null
        }
        Write-Log "Successfully created registry entries for custom notification app: $fAppDisplayName"
    }
    catch {
        Write-Log -Message "Failed to create one or more registry entries for the custom notification app" -Level Error
        Write-Log -Message "Toast Notifications are usually not displayed if the notification app does not exist" -Level Error
    }
}

# Create function to retrieve the last run time of the notification
function Get-NotificationLastRunTime() {
    $LastRunTime = (Get-ItemProperty $global:RegistryPath -Name LastRunTime -ErrorAction Ignore).LastRunTime
    $CurrentTime = Get-Date -Format s
    if (-NOT[string]::IsNullOrEmpty($LastRunTime)) {
        $Difference = ([datetime]$CurrentTime - ([datetime]$LastRunTime))
        $MinutesSinceLastRunTime = [math]::Round($Difference.TotalMinutes)
        Write-Log -Message "Toast notification was previously displayed $MinutesSinceLastRunTime minutes ago"
        $MinutesSinceLastRunTime
    }
}

# Create function to store the timestamp of the notification execution
function Save-NotificationLastRunTime() {
    try {
        if (-NOT(Test-Path -Path $global:RegistryPath)) {
            New-Item -Path $global:RegistryPath -Force | Out-Null
            Write-Log -Message "Successfully created registry path: $global:RegistryPath"
        }

        $CurrentTime = Get-Date -Format s
        Set-ItemProperty -Path $global:RegistryPath -Name "LastRunTime" -Value $CurrentTime -Force
    }
    catch {
        Write-Log -Level Error -Message "Failed to save notification run time: $_"
    }
}

#region Variables
# Setting global script version
$global:ScriptVersion = "3.0.0"
# Setting executing directory
$global:ScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition
# Setting global registry path
$global:RegistryPath = "HKCU:\SOFTWARE\ToastNotificationScript"
# Get user culture for multilanguage support
$userCulture = try { (Get-Culture).Name } catch { Write-Log -Level Error -Message "Failed to get user's local culture: $_" }
# Setting the default culture to en-US. This will be the default language if MultiLanguageSupport is not enabled in the config
$defaultUserCulture = "en-US"
# Temporary location for images if images are hosted online on blob storage or similar
$LogoImageTemp = "$env:TEMP\ToastLogoImage.jpg"
$HeroImageTemp = "$env:TEMP\ToastHeroImage.jpg"
# Setting path to local images
$ImagesPath = "file:///$global:ScriptPath/Images"
#endregion

# Create the global registry path for the toast notification script
if (-NOT(Test-Path -Path $global:RegistryPath)) {
    Write-Log -Message "ToastNotificationScript registry path not found. Creating it: $global:RegistryPath"
    try {
        New-Item -Path $global:RegistryPath -Force | Out-Null
    }
    catch {
        Write-Log -Message "Failed to create the ToastNotificationScript registry path: $global:RegistryPath" -Level Error
        Write-Log -Message "This is required. Script will now exit" -Level Error
        Exit 1
    }
}

# Testing for prerequisites
# Test if the script is being run on a supported version of Windows. Windows 10 AND workstation OS is required
$SupportedWindowsVersion = Get-WindowsVersion
if ($SupportedWindowsVersion -eq $False) {
    Write-Log -Message "Aborting script" -Level Error
    Exit 1
}

# Check if script is running as SYSTEM and exit with error if so
$CurrentUser = [Environment]::UserName
if ($CurrentUser -eq "SYSTEM") {
    Write-Log -Level Error -Message "This script cannot run in SYSTEM context" -IncludeIMEOutput
    Write-Log -Level Error -Message "Toast notifications require user session access and will not work under SYSTEM"
    Exit 1
}

# Testing for blockers of toast notifications in Windows
$WindowsPushNotificationsEnabled = Test-WindowsPushNotificationsEnabled
if ($WindowsPushNotificationsEnabled -eq $False) {
    Enable-WindowsPushNotifications
}
# If no config file is set as parameter, use the default.
# Default is executing directory. In this case, the config-toast.xml must exist in same directory as the Remediate-ToastNotification.ps1 file
if (-NOT($Config)) {
    Write-Log -Message "No config file set as parameter. Using local config file"
    $Config = Join-Path ($global:ScriptPath) "config-toast.xml"
}

# Load config file
$Xml = Get-ToastConfig -ConfigPath $Config

# Check for configuration conflicts
Write-Log -Message "Validating configuration for conflicts and compatibility issues"
$ConflictResults = Test-ConfigConflicts -ConfigXml $Xml

if ($ConflictResults.HasConflicts) {
    Write-Log -Level Error -Message "Critical configuration conflicts detected - script cannot continue safely" -IncludeIMEOutput
    foreach ($Conflict in $ConflictResults.Conflicts) {
        Write-Log -Level Error -Message "CONFLICT: $Conflict" -IncludeIMEOutput
    }
    Exit 1
}

if ($ConflictResults.HasWarnings) {
    Write-Log -Level Warn -Message "Configuration warnings detected - script will continue but behavior may be unexpected" -IncludeIMEOutput
    foreach ($Warning in $ConflictResults.Warnings) {
        Write-Log -Level Warn -Message "WARNING: $Warning" -IncludeIMEOutput
    }
}

# Load xml content into variables
if(-NOT[string]::IsNullOrEmpty($Xml)) {
    try {
        Write-Log -Message "Loading xml content from $Config into variables"
        # Load Toast Notification features
        $ToastEnabled = $Xml.Configuration.Feature | Where-Object {$_.Name -like 'Toast'} | Select-Object -ExpandProperty 'Enabled'
        $PendingRebootUptimeEnabled = $Xml.Configuration.Feature | Where-Object {$_.Name -like 'PendingRebootUptime'} | Select-Object -ExpandProperty 'Enabled'
        $WeeklyMessageEnabled = $Xml.Configuration.Feature | Where-Object {$_.Name -like 'WeeklyMessage'} | Select-Object -ExpandProperty 'Enabled'
        # Load Toast Notification options
        $PendingRebootUptimeTextEnabled = $Xml.Configuration.Option | Where-Object {$_.Name -like 'PendingRebootUptimeText'} | Select-Object -ExpandProperty 'Enabled'
        $MaxUptimeDays = $Xml.Configuration.Option | Where-Object {$_.Name -like 'MaxUptimeDays'} | Select-Object -ExpandProperty 'Value'
        $WeeklyMessageDay = $Xml.Configuration.Option | Where-Object {$_.Name -like 'WeeklyMessageDay'} | Select-Object -ExpandProperty 'Value'
        $WeeklyMessageHour = $Xml.Configuration.Option | Where-Object {$_.Name -like 'WeeklyMessageHour'} | Select-Object -ExpandProperty 'Value'
        # Custom app doing the notification
        $CustomAppEnabled = $Xml.Configuration.Option | Where-Object {$_.Name -like 'CustomNotificationApp'} | Select-Object -ExpandProperty 'Enabled'
        $CustomAppValue = $Xml.Configuration.Option | Where-Object {$_.Name -like 'CustomNotificationApp'} | Select-Object -ExpandProperty 'Value'
        $LogoImageFileName = $Xml.Configuration.Option | Where-Object {$_.Name -like 'LogoImageName'} | Select-Object -ExpandProperty 'Value'
        $HeroImageFileName = $Xml.Configuration.Option | Where-Object {$_.Name -like 'HeroImageName'} | Select-Object -ExpandProperty 'Value'
        # Rewriting image variables to cater for images being hosted online, as well as being hosted locally.
        # Needed image including path in one variable
        if ((-NOT[string]::IsNullOrEmpty($LogoImageFileName)) -OR (-NOT[string]::IsNullOrEmpty($HeroImageFileName)))  {
            $LogoImage = $ImagesPath + "/" + $LogoImageFileName
            $HeroImage = $ImagesPath + "/" + $HeroImageFileName
        }
        $Scenario = $Xml.Configuration.Option | Where-Object {$_.Name -like 'Scenario'} | Select-Object -ExpandProperty 'Type'
        $Action1 = $Xml.Configuration.Option | Where-Object {$_.Name -like 'Action1'} | Select-Object -ExpandProperty 'Value'
        $Action2 = $Xml.Configuration.Option | Where-Object {$_.Name -like 'Action2'} | Select-Object -ExpandProperty 'Value'
        $MultiLanguageSupport = $Xml.Configuration.Text | Where-Object {$_.Option -like 'MultiLanguageSupport'} | Select-Object -ExpandProperty 'Enabled'
        # Load Toast Notification buttons
        $ActionButton1Enabled = $Xml.Configuration.Option | Where-Object {$_.Name -like 'ActionButton1'} | Select-Object -ExpandProperty 'Enabled'
        $ActionButton2Enabled = $Xml.Configuration.Option | Where-Object {$_.Name -like 'ActionButton2'} | Select-Object -ExpandProperty 'Enabled'
        $DismissButtonEnabled = $Xml.Configuration.Option | Where-Object {$_.Name -like 'DismissButton'} | Select-Object -ExpandProperty 'Enabled'
        $SnoozeButtonEnabled = $Xml.Configuration.Option | Where-Object {$_.Name -like 'SnoozeButton'} | Select-Object -ExpandProperty 'Enabled'
        # Multi language support
        if ($MultiLanguageSupport -eq "True") {
            Write-Log -Message "MultiLanguageSupport set to True. Current language culture is $userCulture. Checking for language support"
            # Check config xml if language support is added for the users culture
            if (-NOT[string]::IsNullOrEmpty($xml.Configuration.$userCulture)) {
                Write-Log -Message "Language culture support found, localizing text using $userCulture"
                $XmlLang = $xml.Configuration.$userCulture
            }
            # Else fallback to using default language "en-US"
            elseif (-NOT[string]::IsNullOrEmpty($xml.Configuration.$defaultUserCulture)) {
                Write-Log -Message "Language culture support not found, using $defaultUserCulture as fallback"
                $XmlLang = $xml.Configuration.$defaultUserCulture
            }
        }
        # If multilanguagesupport is set to False use default language "en-US"
        elseif ($MultiLanguageSupport -eq "False") {
            $XmlLang = $xml.Configuration.$defaultUserCulture
        }
        # Regardless of whatever might happen, always use "en-US" as language
        else {
            $XmlLang = $xml.Configuration.$defaultUserCulture
        }
        # Load Toast Notification text
        $PendingRebootUptimeTextValue = $XmlLang.Text | Where-Object {$_.Name -like 'PendingRebootUptimeText'} | Select-Object -ExpandProperty '#text'
        $WeeklyMessageTitleText = $XmlLang.Text | Where-Object {$_.Name -like 'WeeklyMessageTitle'} | Select-Object -ExpandProperty '#text'
        $WeeklyMessageBodyText = $XmlLang.Text | Where-Object {$_.Name -like 'WeeklyMessageBody'} | Select-Object -ExpandProperty '#text'
        $ActionButton1Content = $XmlLang.Text | Where-Object {$_.Name -like 'ActionButton1'} | Select-Object -ExpandProperty '#text'
        $ActionButton2Content = $XmlLang.Text | Where-Object {$_.Name -like 'ActionButton2'} | Select-Object -ExpandProperty '#text'
        $DismissButtonContent = $XmlLang.Text | Where-Object {$_.Name -like 'DismissButton'} | Select-Object -ExpandProperty '#text'
        $SnoozeButtonContent = $XmlLang.Text | Where-Object {$_.Name -like 'SnoozeButton'} | Select-Object -ExpandProperty '#text'
        $AttributionText = $XmlLang.Text | Where-Object {$_.Name -like 'AttributionText'} | Select-Object -ExpandProperty '#text'
        $HeaderText = $XmlLang.Text | Where-Object {$_.Name -like 'HeaderText'} | Select-Object -ExpandProperty '#text'
        $TitleText = $XmlLang.Text | Where-Object {$_.Name -like 'TitleText'} | Select-Object -ExpandProperty '#text'
        $BodyText1 = $XmlLang.Text | Where-Object {$_.Name -like 'BodyText1'} | Select-Object -ExpandProperty '#text'
        $BodyText2 = $XmlLang.Text | Where-Object {$_.Name -like 'BodyText2'} | Select-Object -ExpandProperty '#text'
        $SnoozeText = $XmlLang.Text | Where-Object {$_.Name -like 'SnoozeText'} | Select-Object -ExpandProperty '#text'
	    # Note: Removed DeadlineText for simplified configuration
	    $GreetMorningText = $XmlLang.Text | Where-Object {$_.Name -like 'GreetMorningText'} | Select-Object -ExpandProperty '#text'
	    $GreetAfternoonText = $XmlLang.Text | Where-Object {$_.Name -like 'GreetAfternoonText'} | Select-Object -ExpandProperty '#text'
	    $GreetEveningText = $XmlLang.Text | Where-Object {$_.Name -like 'GreetEveningText'} | Select-Object -ExpandProperty '#text'
	    $MinutesText = $XmlLang.Text | Where-Object {$_.Name -like 'MinutesText'} | Select-Object -ExpandProperty '#text'
	    $HourText = $XmlLang.Text | Where-Object {$_.Name -like 'HourText'} | Select-Object -ExpandProperty '#text'
        $HoursText = $XmlLang.Text | Where-Object {$_.Name -like 'HoursText'} | Select-Object -ExpandProperty '#text'
	    $ComputerUptimeText = $XmlLang.Text | Where-Object {$_.Name -like 'ComputerUptimeText'} | Select-Object -ExpandProperty '#text'
        $ComputerUptimeDaysText = $XmlLang.Text | Where-Object {$_.Name -like 'ComputerUptimeDaysText'} | Select-Object -ExpandProperty '#text'
        Write-Log -Message "Successfully loaded xml content from $Config"
    }
    catch {
        Write-Log -Message "Xml content from $Config was not loaded properly"
        Exit 1
    }
}

if ($CustomAppEnabled -eq "True") {
    # Hardcoding the AppID. Only the display name is interesting, thus this comes from the config.xml
    Register-CustomNotificationApp -fAppID "Toast.Custom.App" -fAppDisplayName $CustomAppValue
}
# Downloading images into user's temp folder if images are hosted online
if ($LogoImageFileName -match "^https?://") {
    $DownloadedLogoPath = Get-ToastImage -ImageUrl $LogoImageFileName -LocalPath $LogoImageTemp -ImageType "LogoImage"
    if ($DownloadedLogoPath) {
        $LogoImage = $DownloadedLogoPath
    }
}

if ($HeroImageFileName -match "^https?://") {
    $DownloadedHeroPath = Get-ToastImage -ImageUrl $HeroImageFileName -LocalPath $HeroImageTemp -ImageType "HeroImage"
    if ($DownloadedHeroPath) {
        $HeroImage = $DownloadedHeroPath
    }
}
# Running Pending Reboot Checks
if ($PendingRebootUptimeEnabled -eq "True") {
    $Uptime = Get-DeviceUptime
    Write-Log -Message "PendingRebootUptimeEnabled set to True. Checking for device uptime. Current uptime is: $Uptime days"
}

# Check for WeeklyMessage scenario
if ($WeeklyMessageEnabled -eq "True") {
    Write-Log -Message "WeeklyMessage feature is enabled, checking trigger conditions"

    if (Test-WeeklyMessageTrigger -TargetDay $WeeklyMessageDay -TargetHour ([int]$WeeklyMessageHour)) {
        # Set a flag for WeeklyMessage detection
        $WeeklyMessageTriggered = $true
    }
}
# Registry setup for notification apps is now handled in Show-ToastNotification function when the app is determined

# PowerShell app registry setup is now handled automatically in Show-ToastNotification function when needed

# Building personalized greeting with given name
Write-Log -Message "Building personalized greeting with given name"
$Hour = (Get-Date).TimeOfDay.Hours
if (($Hour -ge 0) -AND ($Hour -lt 12)) {
    Write-Log -Message "Using morning greeting"
    $Greeting = $GreetMorningText
}
elseif (($Hour -ge 12) -AND ($Hour -lt 16)) {
    Write-Log -Message "Using afternoon greeting"
    $Greeting = $GreetAfternoonText
}
else {
    Write-Log -Message "Using evening greeting"
    $Greeting = $GreetEveningText
}
$GivenName = Get-GivenName
$HeaderText = "$Greeting $GivenName"
# Build toast notification XML based on configuration
Write-Log -Message "Building toast notification XML based on button configuration"

# Check if uptime information should be included
$IncludeUptime = ($PendingRebootUptimeTextEnabled -eq "True") -AND ($Uptime -gt $MaxUptimeDays)
if ($IncludeUptime) {
    Write-Log -Message "Including uptime information in toast notification (uptime: $Uptime days exceeds maximum: $MaxUptimeDays days)"
}

# Determine which buttons to include based on configuration
if ($SnoozeButtonEnabled -eq "True") {
    Write-Log -Message "Creating toast with snooze button (includes action button and dismiss button)"
    $Toast = New-ToastXml -IncludeSnoozeButton $true -IncludeUptimeInfo $IncludeUptime -UptimeDays $Uptime -IsWeeklyMessage ($WeeklyMessageTriggered -eq $true)
}
elseif ($ActionButton2Enabled -eq "True") {
    Write-Log -Message "Creating toast with both action buttons and dismiss button"
    $Toast = New-ToastXml -IncludeActionButton1 $true -IncludeActionButton2 $true -IncludeDismissButton $true -IncludeUptimeInfo $IncludeUptime -UptimeDays $Uptime -IsWeeklyMessage ($WeeklyMessageTriggered -eq $true)
}
else {
    # Standard button combinations
    $IncludeAction1 = ($ActionButton1Enabled -eq "True")
    $IncludeDismiss = ($DismissButtonEnabled -eq "True")

    if ($IncludeAction1 -and $IncludeDismiss) {
        Write-Log -Message "Creating toast with action button and dismiss button"
    }
    elseif ($IncludeAction1 -and -not $IncludeDismiss) {
        Write-Log -Message "Creating toast with action button only"
    }
    elseif (-not $IncludeAction1 -and $IncludeDismiss) {
        Write-Log -Message "Creating toast with dismiss button only"
    }
    else {
        Write-Log -Message "Creating toast with no action buttons"
    }

    $Toast = New-ToastXml -IncludeActionButton1 $IncludeAction1 -IncludeDismissButton $IncludeDismiss -IncludeUptimeInfo $IncludeUptime -UptimeDays $Uptime -IsWeeklyMessage ($WeeklyMessageTriggered -eq $true)
}

# Running the Display-notification function depending on selections and variables
# Toast used for WeeklyMessage
if ($WeeklyMessageEnabled -eq "True" -AND $WeeklyMessageTriggered -eq $true) {
    Write-Log -Message "Displaying WeeklyMessage toast notification for $WeeklyMessageDay at $WeeklyMessageHour`:00"
    Show-ToastNotification
    # Stopping script. No need to accidentally run further toasts
    break
}

# Toast used for PendingReboot check and considering OS uptime
if (($PendingRebootUptimeEnabled -eq "True") -AND ($Uptime -gt $MaxUptimeDays)) {
    Write-Log -Message "Toast notification is used in regards to pending reboot. Uptime count is greater than $MaxUptimeDays"
    Show-ToastNotification
    # Stopping script. No need to accidently run further toasts
    break
}

# Display default toast if both trigger features are disabled
if (($WeeklyMessageEnabled -ne "True") -AND ($PendingRebootUptimeEnabled -ne "True")) {
    Write-Log -Message "Both WeeklyMessage and PendingRebootUptimeEnabled features are disabled. Displaying default toast notification"
    Show-ToastNotification
    # Stopping script. No need to accidentally run further toasts
    break
}

# Final fallback: if we reach here, no conditions were met
Write-Log -Level Warn -Message "No toast notification conditions were fulfilled - script completed without displaying notification" -IncludeIMEOutput
