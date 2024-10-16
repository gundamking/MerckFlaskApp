# BeagleBone Device Management Application

## Overview
The **BeagleBone Device Management Application** is a web-based tool designed to monitor, manage, and check the availability of BeagleBone devices across multiple sites. It provides real-time information on each device's status, location, and ownership, allowing for quick troubleshooting and issue resolution. The application supports functionality such as device health checks via SSH and automated pings, allowing business owners to quickly determine if devices are online and functioning.

This application also includes the ability to upload device details via CSV and manage device configurations easily through a user-friendly interface.

---

## Business Use Case
In large, multi-site environments, BeagleBone devices are often used for automation, monitoring, and data collection. Ensuring the uptime of these devices is critical, and manually checking device statuses can be time-consuming. This application centralizes the management of these devices, allowing users to:

- **View device details** including hostname, site, IP address, and owner.
- **Check device status** by pinging the device and performing SSH health checks.
- **Identify and contact** the responsible owner when a device is down or experiencing issues.

---

## BeagleBone Overview
[BeagleBone](https://beagleboard.org/) is a low-cost, single-board computer used for a variety of IoT (Internet of Things) applications. It is commonly employed for tasks like industrial automation, sensor control, and data collection. In this application, BeagleBone devices are used across sites and are monitored to ensure they remain accessible and functional.

**BeagleBone Specs:**
- **CPU**: ARM Cortex-A8
- **RAM**: 512 MB
- **Connectivity**: Ethernet, USB, GPIO

---

## INVICRO IPACS Sync Client
The **INVICRO IPACS Sync Client** is used for synchronizing medical and imaging data across different sites. Ensuring that the BeagleBone devices tied to this system are online and accessible is crucial for maintaining the availability of imaging and medical data. The BeagleBone devices act as data collectors in this ecosystem.

---

## Key Features
- **Centralized Device Management**: View all devices in one place, with quick access to information such as hostname, site, owner, and IP address.
- **Device Status Checks**: Automatically ping devices and perform SSH health checks to verify if the devices are operational.
- **CSV Upload**: Bulk upload device information via CSV for easy onboarding and updates.
- **Real-Time Notifications**: In future versions, the application will allow email notifications to be sent to business owners when devices are down.
- **Device Ownership Information**: Quickly identify who to contact when a device is not functioning.

---

## Technology Stack
- **Backend**: Flask (Python)
- **Database**: SQLite (via SQLAlchemy ORM)
- **Frontend**: HTML/CSS (Bootstrap for responsive design)
- **SSH Communication**: Paramiko (for SSH health checks)
- **Ping Functionality**: ping3 library (to check device availability)
- **File Upload**: CSV handling via Pandas

---

## Installation

### Prerequisites
- Python 3.6+
- OpenSSL 1.1+ (required for `scrypt` encryption in `hashlib`)

### Step-by-Step Guide

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/your-repo/beaglebone-device-manager.git
   cd beaglebone-device-manager
