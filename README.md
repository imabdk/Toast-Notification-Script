# Toast Notification Script

## Current version: 2.1.0

Download the complete Windows 10 Toast Notification Script: https://github.com/imabdk/Toast-Notification-Script/blob/master/ToastNotificationScript2.1.0.zip

Blog posts, documentation as well as if any questions, please use: https://www.imab.dk/windows-10-toast-notification-script/

## What's New
 - 2.1.0 - Added a second action button: ActionButton2
   - This allows you to have 2 separate actions. Example: Action1 starts a task sequence, action2 sends the user to a web page for more info
   - This will require new config.xml files
  - Reworked Get-GivenName function
    - Now looks for given name in 1) local Active Directory 2) with WMI and the ConfigMgr client 3) directly in registry
    - Now checks 3 places for given name, and if no given name found at all, a placeholder will be used
  - Fixed CustomAudioToSpeech option
    - This part haven't worked for a while it seems
    - Only works properly with en-US language
  - Added Enable-WindowsPushNotifications function // Thank you @ Trevor Jones: https://smsagent.blog/2020/11/12/prevent-users-from-disabling-toast-notifications-can-it-be-done/
    - This will force enable Windows toast notification for the logged on user, if generally disabled
    - A Windows service will be restarted in the process in the context of the user
