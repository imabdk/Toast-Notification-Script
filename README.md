# Toast Notification Script

## Current Version: 3.0.0 (Microsoft Intune)

🚀 **NEW:** Version 3.0.0 has been completely rewritten specifically for **Microsoft Intune and the remediations feature**.

![Toast Notification Script Examples](Screenshots/toast-notification-script.png)

### Quick Download

**For Microsoft Intune (Recommended):**
- [Remediate-ToastNotification.ps1](Remediate-ToastNotification.ps1) - Main script for toast notification delivery
- [Detect-ToastNotification.ps1](Detect-ToastNotification.ps1) - Detection script for Intune deployment
- [config-toast-weeklymessage.xml](config-toast-weeklymessage.xml) - Configuration example for weekly messages
- [config-toast-pendingreboot.xml](config-toast-pendingreboot.xml) - Configuration example for pending reboot notifications

### Documentation & Support

📖 **Documentation:** [https://www.imab.dk/windows-10-toast-notification-script/](https://www.imab.dk/windows-10-toast-notification-script/)

❓ **Questions & Issues:** Please visit the blog post above for comprehensive documentation and support.

---

## Version 3.0.0 - Microsoft Intune Edition

### Overview

The Toast Notification Script has been completely rewritten for **Microsoft Intune** to provide native Windows toast notifications to end users. This version is specifically optimized for Intune's remediation workflow with enhanced international compatibility and intelligent scheduling.

### Key Features

- ✅ **Microsoft Intune Optimized**: Designed specifically for Intune remediation deployment with proper exit codes
- 📅 **Weekly Messaging**: Flexible day/hour targeting with support for multiple days and "any time" scheduling
- 📊 **Enhanced Logging**: Multi-level logging with rotation, IME integration, and fallback mechanisms
- 👤 **Personalized Experience**: Dynamic time-based greetings with user's first name and comprehensive fallback chains
- 🎯 **Multiple Notification Types**: Weekly reminders, reboot notifications, general announcements

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

> **Note**: This version is specifically built to work with PowerShell Constrained Language Mode, ensuring compatibility with secure Intune environments.

### Quick Start

1. **Download the files**
2. **Configure** the `config-toast.xml` file for your organization and host it online
3. **Deploy** in Microsoft Intune:
   - **Detection Script**: `Detect-ToastNotification.ps1`
   - **Remediation Script**: `Remediate-ToastNotification.ps1`
   - **Schedule**: Configure based on your notification requirements

### Intune Configuration

![Intune Remediation Configuration](Screenshots/intune-remediation-config-example.png)

### International Support

Version 3.0.0 includes enhanced international compatibility:

- **Numeric Day Format**: Uses 1-7 (Monday-Sunday) instead of localized day names
- **Multi-Language Support**: XML configuration supports multiple languages (en-US, da-DK, sv-SE included)
- **Culture Independent**: Works consistently across all Windows language installations
- **Fallback Mechanisms**: Comprehensive fallbacks for various regional settings

### Configuration Highlights

The `config-toast.xml` file supports:

- **Feature Toggles**: Enable/disable toast notifications, weekly messages, pending reboot checks
- **Scheduling Options**: Flexible day/hour targeting (including "any time" options)
- **Visual Customization**: Custom logos, hero images, and notification text
- **Button Configuration**: Action buttons, dismiss buttons, snooze functionality
- **Language Support**: Multi-language text definitions

### What's New in 3.0.0

- **Complete Rewrite**: Built from ground up for Microsoft Intune
- **Enhanced Scheduling**: Support for multiple days and flexible hour targeting
- **Improved Logging**: Advanced logging with rotation and IME integration
- **Smart Detection**: Intelligent detection script for proper Intune workflow
- **Configuration Validation**: Comprehensive conflict detection and validation
- **Personalized Greetings**: Dynamic time-based user greetings with fallbacks

---

## Legacy Versions (Configuration Manager)

### Version 2.3.0 - Configuration Manager Edition

For organizations still using **Configuration Manager (SCCM)**, the legacy version remains available:

**Download:** [ToastNotificationScript2.3.0.zip](https://github.com/imabdk/Toast-Notification-Script/blob/master/ToastNotificationScript2.3.0.zip)

#### Legacy Features (v2.3.0)
- Custom notification app registration
- Software Center integration
- Traditional ConfigMgr deployment model
- PowerShell app notifications

> ⚠️ **Note**: The legacy ConfigMgr version (2.x) is no longer actively developed. Organizations are encouraged to migrate to Microsoft Intune and use version 3.0.0 for enhanced features and ongoing support.

---

## Support & Community

- 📝 **Blog**: [https://www.imab.dk/windows-10-toast-notification-script/](https://www.imab.dk/windows-10-toast-notification-script/)
- 🐛 **Issues**: [GitHub Issues](https://github.com/imabdk/Toast-Notification-Script/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/imabdk/Toast-Notification-Script/discussions)

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Author

**Martin Bengtsson**
- Website: [https://www.imab.dk](https://www.imab.dk)
- GitHub: [@imabdk](https://github.com/imabdk)

---

*Version 3.0.0 - Rewritten for Microsoft Intune | November 2025*
