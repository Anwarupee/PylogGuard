# PylogGuard

PyLogGuard is a Python-based CLI project for log management and attack simulation.
It provides CRUD operations for users, roles, logs, and supports basic attack detection & simulation (e.g., DDoS).

## ✨ Features

User Management (Create, Read, Update, Delete users)

Role Management (Admin, Analyst, etc.)

Log Management (Store attack logs, filter by user or type)

DDoS Simulation

Log generator for attack traffic

Simple detector to analyze logs

Modular CLI Menus

Users

Logs

Detector

Generator

## 📂 Project Structure  

```plaintext
PyLogGuard/
├── main.py              # Main CLI menu
├── models/              # Database models
│   ├── user_model.py
│   ├── role_model.py
│   ├── log_model.py
│   └── role_model.py
├── tools/               # Extra utilities
│   ├── gen_ddos.py
│   └── detect_ddos.py
├── database/            # DB setup
│   └── db_connection.py
└── README.md
```

## 🚀 Installation

Clone this repository:
```
git clone https://github.com/<your-username>/PyLogGuard.git
cd PyLogGuard
```

Install dependencies:
```
pip install -r requirements.txt
```

Setup your database (MySQL or SQLite).
Adjust connection in database/db_connection.py.

## ▶️ Usage

Run the program:
```
python main.py
```
Main Menu

After login, the main menu includes:
```
1. Users
2. Logs
3. Detector
4. Generator
```
```
Example: Create User
Choose: 1
1. Create User
2. Read User
3. Update User
4. Delete User
```
## ⚡ Attack Simulation
Generate Fake DDoS Logs
```
python -m tools.gen_ddos <IP> <hits> <attack_id> <created_by>
```
Detect DDoS in Logs
```
python -m tools.detect_ddos
```

## 🛠️ Tech Stack

Python 3.10+

MySQL / SQLite

CLI-based menu system

## 📌 Notes

Currently supports DDoS attack simulation and detection.

Phishing support was planned but later removed for project scope.

Can be extended into a portfolio project (e.g., Web dashboard).
