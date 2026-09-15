# Company Device Security Management System

##  Overview

The **Company Device Security Management System** is a web-based application designed to help organizations monitor and manage the security status of company computers and other devices.

The system allows an administrator to register devices, monitor their security conditions, identify devices that may be at risk, and maintain information about security controls such as antivirus, firewall, backup, and online status.

##  Objectives

The main objectives of this system are to:

* Monitor company devices from a central dashboard.
* Identify devices that are not fully secure.
* Track antivirus, firewall, and backup status.
* Monitor whether devices are online or offline.
* Allow administrators to add and manage devices.
* Provide a simple security overview through a dashboard.
* Help reduce the risk of company data loss.

##  Main Features

### 1. Admin Dashboard

Provides an overview of the organization's devices and their security status.

### 2. Device Management

Administrators can:

* Add new devices.
* View registered devices.
* Update device information.
* Monitor device security status.

### 3. Security Monitoring

The system monitors security controls including:

| Security Control | Description                                    |
| ---------------- | ---------------------------------------------- |
| Antivirus        | Checks whether antivirus protection is enabled |
| Firewall         | Checks whether the firewall is enabled         |
| Backup           | Checks whether required backups are enabled    |
| Online Status    | Shows whether the device is currently online   |

### 4. Risk Detection

A device can be identified as **At Risk** when one or more required security controls are disabled.

For example:

```text
Antivirus: Enabled
Firewall: Enabled
Backup: Disabled

Status: AT RISK
```

A fully protected device can be displayed as:

```text
Antivirus: Enabled
Firewall: Enabled
Backup: Enabled

Status: SECURE
```

##  System Architecture

The system consists of three main parts:

```text
        Administrator
              │
              ▼
       Web Application
        (React / Next.js)
              │
              ▼
        Backend / API
              │
              ▼
       PostgreSQL Database
              │
              ▼
       Device Information
```

##  Technologies Used

### Frontend

* React
* Next.js
* JavaScript
* JSX
* HTML
* CSS

### Backend

* Node.js
* API endpoints

### Database

* PostgreSQL

### Development Tools

* Visual Studio Code
* Git
* GitHub
* Terminal

##  Database

The system stores information about registered devices and their security status.

Example device information:

```text
Device Name
Operating System
Antivirus Status
Firewall Status
Backup Status
Online Status
Security Status
```

Example:

| Device       | OS         | Antivirus | Firewall | Backup | Online | Status  |
| ------------ | ---------- | --------- | -------- | ------ | ------ | ------- |
| Office-PC-01 | Windows 11 | ✓         | ✓        | ✓      | ✓      | Secure  |
| Test-Laptop  | Windows 11 | ✓         | ✓        | ✓      | ✓      | Secure  |
| HP Omen      | Windows 11 | ✗         | ✓        | ✓      | ✓      | At Risk |

##  Installation
