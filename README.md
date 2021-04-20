# Toast Notification Script

## Current version: 2.2.0

Download the complete Windows 10 Toast Notification Script: https://github.com/imabdk/Toast-Notification-Script/blob/master/ToastNotificationScript2.2.0.zip

Blog posts, documentation as well as if any questions, please use: https://www.imab.dk/windows-10-toast-notification-script/

## What's New

- 2.2.0 - Added built-in prevention of having multiple toast notifications to be displayed in a row
   - This is something that can happen, if a device misses a schedule in ConfigMgr
   - The nature of ConfigMgr is to catch up on the missed schedule, and this can lead to multiple toast notifications being displayed
   - This will require new config.xml files
  - Added the ability to run the script coming from SYSTEM context
   - This has proven to only work with packages/programs/task sequences and when testing with psexec
   - Running the script in SYSTEM, with the script feature in configmgr and proactive remediations in Intune, still yields unexpected results
