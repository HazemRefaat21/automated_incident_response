# 🛡️ Wazuh + Django SIEM System

> نظام SIEM متكامل يعتمد على Wazuh لجمع وتحليل الـ logs، Django كـ Backend، وClassification Engine للكشف عن الهجمات.

## Architecture
- **Wazuh Stack:** Manager + Indexer + Dashboard + Agent
- **Backend:** Django 5.x + Django REST Framework
- **Database:** PostgreSQL
- **Queue:** Celery + Redis
- **Response:** iptables + psutil

## Quick Start
```bash
# Clone the repo
git clone <repo-url>
cd siem-project

# Setup environment
cp .env.example .env
# Edit .env with your values

# Activate venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run Django
cd django-backend
python manage.py migrate
python manage.py runserver
```

## Sprints
- [x] Sprint 0: Environment Setup
- [ ] Sprint 1: Wazuh Installation & Log Collection
- [ ] Sprint 2: Django Backend Foundation
- [ ] Sprint 3: Wazuh ↔ Django Integration
- ...

## Status: 🔄 In Progress — Sprint 0
