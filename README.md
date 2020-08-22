# Toast Notification Script

Current version: 2.0.0

Download the complete Windows 10 Toast Notification Script: https://github.com/imabdk/Toast-Notification-Script/blob/master/ToastNotificationScript2.0.0.zip

Blog posts, documentation as well as if any questions, please use: https://www.imab.dk/windows-10-toast-notification-script/

          ** Most of the work done in version 2.0.0 is done by Chad Bower // @Brower_Cha on Twitter **
          ** I have added the additional protocols/scripts and rewritten some minor things **
          ** As well as added support for dynamic deadline retrieval for software updates **
          ** Stuff has been rewritten to suit my understanding and thoughts of the script **

2.0.0 -   Huge changes to how this script handles custom protocols
            - Added Support for Software Updates : Searches for an update (IPU) and will store in variable
            - Added Support for Custom Actions/Protocols within the script under user context removing the need for that to be run under SYSTEM/ADMIN
                <Option Name="Action" Value="ToastRunUpdateID:" />
            - Added Support to dynamically create Custom Action Scripts to support Custom Protocols
            - Added New XML Types for SoftwareUpdates : 
                <Option Name="RunUpdateTitle" Enabled="True" Value="Version 1909" />
                <Option Name="RunUpdateID" Enabled="True" Value="3012973" />
            - Added support for getting deadline date/time dynamically for software updates
