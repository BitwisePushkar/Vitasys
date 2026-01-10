# Vitasys

> Scalable, real-time **Hospital Management System** built to streamline healthcare workflows — connecting **patients, doctors, appointments, consultations, and prescriptions** into one unified platform.

Vitasys delivers a seamless digital healthcare experience with **real-time communication**, **secure data handling**, and **high-performance APIs**.

---

## Tech Stack

| Layer      | Technologies                   |
| ---------- | ------------------------------ |
| Backend    | Django · Django REST Framework |
| Database   | PostgreSQL                     |
| Realtime   | WebSockets · Redis             |
| Background | Celery · Celery Beat · Redis   |
| Auth       | JWT · Email Verification       |
| Storage    | AWS S3                         |
| Infra      | Docker · Docker Compose · uv   |

---

## What Vitasys Does

### Authentication

Complete auth lifecycle:

* Register · Login · Logout
* Refresh Tokens (JWT)
* Email Verification
* Password Reset

---

### User Management

* Patient & Doctor Profiles
* Role-Based Access Control
* Avatar Upload
* Account Management

---

### Doctor Dashboard

* Patient Management
* Appointment Scheduling
* Prescription Creation
* Access Medical History
* Consultation Tools

---

### Patient Dashboard

* Book & Manage Appointments
* View Prescriptions
* Access Medical Records
* Track Health History
* Join Consultations

---

### Appointments

* Book · Reschedule · Cancel
* Doctor Availability Tracking
* Automated Reminders
* Status Updates

---

### Prescriptions

* Digital Prescriptions
* Medication Details
* Download & History
* Secure Doctor-Issued Records

---

### Video Consultation

* Real-time Doctor ↔ Patient Calls
* Secure, Low-Latency Communication

---

### Chat System

* Private Chat Rooms
* Doctor-Patient Messaging
* Powered by **WebSockets**

---

### Media Sharing

* Upload Images · Files · Reports
* Secure storage via **AWS S3**

---

### Community

* Health Discussions
* Public & Private Rooms
* Patient Engagement

---

### Notifications

* Real-time Alerts
* Appointment Reminders
* System Updates
* Unread Counts & Preferences

---

### Dashboard & Analytics

* Personal Health Insights
* Appointment Statistics
* Doctor Analytics
* Patient Overview

---

## Real-Time Capabilities

Powered by **WebSockets + Redis**

* Live Chat Messaging
* Instant Notifications
* Real-time Appointment Updates
* Active Session Tracking

---

## Background Processing

Powered by **Celery + Redis**

* Email Notifications
* Appointment Reminders
* Scheduled Jobs
* System Alerts

---

## System Highlights

* Dual Dashboard (**Doctor & Patient**)
* Real-time Communication (**Chat + Video**)
* Scalable Architecture
* Cloud Storage Integration
* Async & High-Performance APIs

---

## Project Structure

```text
Vitasys/ (Root)
├── Vitasys/ (Main Folder)
│   ├── Vitasys/ (Core Settings)
│   ├── manage.py
│   └── apps/ (auth, appointments, etc.)
├── Dockerfile
├── docker-compose.yml
├── pyproject.toml
└── uv.lock
```

---

## Local Setup

### Prerequisites

* Python 3.10+
* uv
* PostgreSQL
* Redis

---

### Installation

```bash
git clone <repo>
cd Vitasys

uv sync
```

---

### Run Migrations

```bash
uv run python Vitasys/manage.py migrate
```

---

### Start Server

```bash
uv run python Vitasys/manage.py runserver
```

---

### API Docs

```
http://localhost:8000/api/docs
```

---

## Docker Setup

```bash
docker-compose up --build
```

---

## Usage

### With `uv run`

```bash
uv run python Vitasys/manage.py runserver
```

---

### With Virtual Environment

```bash
source .venv/bin/activate   # Linux/macOS
.venv\Scripts\Activate.ps1  # Windows

python Vitasys/manage.py runserver
```