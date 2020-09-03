# Toast Notification Script

###### Current version: 2.0.1

Download the complete Windows 10 Toast Notification Script: https://github.com/imabdk/Toast-Notification-Script/blob/master/ToastNotificationScript2.0.1.zip

Blog posts, documentation as well as if any questions, please use: https://www.imab.dk/windows-10-toast-notification-script/

## What's New
- 2.0.1 - Updated custom action scripts!
  - Moved all custom action scripts into the user's profile in $env:APPDATA\ToastNotificationScript
    - $env:ALLUSERSPROFILE was used previously. This is a bad location if device is used by multiple users due to permission issues
  - Updated all custom action scripts to invoke their respective action via WMI
    - Rewritten all custom action scripts
  - Added logic allowing new custom action scripts to be created if necessary
    - Now checks script version in registry
    - If newer version is available from the script, new custom action scripts will be created
      - This allows me to make sure the relevant scripts are in place in case I change something along the way
  - Modified script output of custom script for RunPackageID to pick up Program ID dynamically
    - Added support for getting deadline date/time dynamically for applications     
      - Configure DynamicDeadline with the Application ID
