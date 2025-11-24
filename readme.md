# 🏥 Vitasys – Hospital Management System

A scalable, real-time **Hospital Management System** powered by **FastAPI**.
Designed to streamline healthcare workflows — **patients ↔ doctors ↔ appointments ↔ consultations ↔ prescriptions** — all in one platform.

---

## 🚀 Tech Stack

`Django : Python : PostgreSQL :  Redis : WebSockets : Celery : Celery Beat : JWT : AWS S3 : Docker`

---

## 🌟 Core Functionality

### 🔐 Auth

Register · Login · Logout · Refresh Token · Password Reset · Email Verification

---

### 👤 Users

Patient & Doctor Profiles · Role-based Access · Avatar Upload · Account Management

---

### 🧑‍⚕️ Doctor Dashboard

Patient Management · Appointment Scheduling · Prescription Creation
Medical History Access · Consultation Tools

---

### 🧑 Patient Dashboard

Book Appointments · View Prescriptions · Medical Records
Track Health History · Join Consultations

---

### 📅 Appointments

Book · Reschedule · Cancel · Doctor Availability
Automated Reminders & Status Tracking

---

### 💊 Prescriptions

Digital Prescriptions · Medication Details · Download & History
Doctor-issued secure records

---

### 🎥 Video Consultation

Real-time Doctor ↔ Patient Video Calls
Secure & low-latency communication

---

### 💬 Chat System

Private Chat Rooms · Doctor-Patient Messaging
Real-time messaging powered by **WebSockets**

---

### 📂 Media Sharing

Upload & Share Images · Files · Medical Reports
Stored securely using **AWS S3**

---

### 🌐 Community

Health Discussions · Public/Private Rooms · Patient Engagement
Knowledge sharing between users

---

### 🔔 Notifications

Real-time Alerts · Appointment Reminders · System Updates
Unread Counts & Preferences

---

### 📊 Dashboard

Personal Health Insights · Appointment Stats
Doctor Analytics & Patient Overview

---

## ⚡ Real-Time Features

Powered by **WebSockets + Redis**

* Live Chat Messaging
* Instant Notifications
* Real-time Appointment Updates
* Active Session Tracking

---

## 🔄 Background Tasks

Powered by **Celery + Redis**

* Email Notifications
* Appointment Reminders
* Scheduled Jobs
* System Alerts

---

## 🧠 System Highlights

* Dual Dashboard (**Doctor & Patient**)
* Real-time Communication (Chat + Video)
* Scalable Architecture
* Cloud Storage Integration
* Async & High Performance APIs

---

## ▶ Setup (Local)

```bash
git clone <repo>
cd vitasys

python -m venv venv
source venv/bin/activate   # windows: venv\Scripts\activate

pip install -r requirements.txt

uvicorn app.main:app --reload --port 80
```

Docs → `http://localhost/api/docs`

---

## 🐳 Setup (Docker)

```bash
docker-compose up --build
```