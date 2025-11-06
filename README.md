# Toast Notification Script

## Current Version: 3.0.0

🚀 **NEW:** Version 3.0.0 has been completely rewritten specifically for **Microsoft Intune** and the **Remediations** feature.

![Toast Notification Script Examples](Screenshots/toast-notification-script.png)

### Quick Download

- [Remediate-ToastNotification.ps1](Remediate-ToastNotification.ps1) - Main script for toast notification delivery
- [Detect-ToastNotification.ps1](Detect-ToastNotification.ps1) - Detection script for Intune deployment
- [config-toast-weeklymessage.xml](config-toast-weeklymessage.xml) - Configuration example for weekly messages
- [config-toast-pendingreboot.xml](config-toast-pendingreboot.xml) - Configuration example for pending reboot notifications

### Documentation & Support

📖 **Documentation:** [https://www.imab.dk/windows-10-toast-notification-script/](https://www.imab.dk/windows-10-toast-notification-script/)

❓ **Questions & Issues:** Please visit the blog post above for documentation and support.

---

## Version 3.0.0 Overview

The Toast Notification Script has been completely rewritten to provide native Windows toast notifications through Microsoft Intune's Remediations feature.

### Key Features & What's New

- ✅ **Microsoft Intune Ready**: Built with proper exit codes and Remediations workflow integration
- 📅 **Flexible Scheduling**: Day/hour targeting with support for multiple days and "any time" scheduling
- 📊 **Multi-Level Logging**: Logging with rotation, IME integration, and fallback mechanisms
- 👤 **Personalized Experience**: Dynamic time-based greetings with user's first name and fallback chains
- 🎯 **Multiple Notification Types**: Weekly reminders, reboot notifications, general announcements
- 🔧 **Smart Detection**: Detection script for proper remediation workflow
- ✔️ **Configuration Validation**: Conflict detection and validation
- 🌍 **PowerShell CLM Compatible**: Works in Constrained Language Mode for secure environments

### Supported Scenarios

- **Weekly Reminders**: Scheduled notifications for routine communication and announcements
- **Reboot Notifications**: Uptime-based restart reminders for system maintenance  
- **General Announcements**: Flexible messaging for various organizational scenarios
- **Application Deployment**: Integration with Company Portal for software deployment notifications

### Requirements

- Windows 10 version 1709 or later / Windows 11
- PowerShell 5.1 or later
- Microsoft Intune managed device
- User context execution (not SYSTEM)
- Internet connectivity for online configuration files

### Quick Start

1. **Download the files**
2. **Configure** the `config-toast.xml` file for your organization and host it online
3. **Deploy** in Microsoft Intune Remediations:
   - **Detection Script**: `Detect-ToastNotification.ps1`
   - **Remediation Script**: `Remediate-ToastNotification.ps1`
   - **Schedule**: Configure based on your notification requirements

### Intune Configuration

![Intune Remediation Configuration](Screenshots/intune-remediation-config-example.png)


### Configuration Highlights

The `config-toast.xml` file supports:

- **Feature Toggles**: Enable/disable toast notifications, weekly messages, pending reboot checks
- **Scheduling Options**: Flexible day/hour targeting (including "any time" options)
- **Visual Customization**: Custom logos, hero images, and notification text
- **Button Configuration**: Action buttons, dismiss buttons, snooze functionality
- **Language Support**: Multi-language text definitions

---

## Legacy Versions (Configuration Manager)

### Version 2.3.0 - Configuration Manager Edition

For organizations still using **Configuration Manager (SCCM)**, the legacy version remains available:

**Download:** [ToastNotificationScript2.3.0.zip](https://github.com/imabdk/Toast-Notification-Script/blob/master/ToastNotificationScript2.3.0.zip)

#### Legacy Features (v2.3.0)
- Custom notification app registration
- Software Center integration
- Integration to task sequences
- Integration to applications and packages

> ⚠️ **Note**: The legacy ConfigMgr version (2.x) is no longer actively developed. Organizations are encouraged to migrate to Microsoft Intune and use version 3.0.0 for additional features and ongoing support.

---

## Support & Community

- 📝 **Blog**: [https://www.imab.dk/windows-10-toast-notification-script/](https://www.imab.dk/windows-10-toast-notification-script/)
- 🐛 **Issues**: [GitHub Issues](https://github.com/imabdk/Toast-Notification-Script/issues)

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Author

**Martin Bengtsson**
- Website: [https://www.imab.dk](https://www.imab.dk)
- GitHub: [@imabdk](https://github.com/imabdk)

---