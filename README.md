# Automated Incident Response (SIEM)

An end-to-end **Security Information & Event Management** pipeline that detects
web/host attacks with **Wazuh**, classifies them in a **Django** backend, and
**automatically responds** (block IP, kill process, notify) — with a Django admin
console and a **Kibana** dashboard for visibility.

---

## How it works (the pipeline)

```
                ┌─────────────┐        access log         ┌──────────────────┐
   HTTP traffic │   Django    │ ───────────────────────▶  │   Wazuh Agent    │
  ───────────▶  │  (your app) │  django_access.log        │  (tails the log) │
                └─────────────┘                            └────────┬─────────┘
                                                                    │ events
                                                                    ▼
                                                          ┌──────────────────┐
                                                          │  Wazuh Manager   │
                                                          │ (web ruleset →   │
                                                          │  raises alerts)  │
                                                          └────────┬─────────┘
                                                                   │ custom-django
                                                                   │ integration
                                                                   ▼  (HTTP POST)
   ┌───────────────────────────── Django backend ──────────────────────────────┐
   │  POST /api/alerts/ingest/                                                   │
   │      │                                                                      │
   │      ▼                                                                      │
   │  alerts/hooks.py   ── classifies → attack_type + severity (from DB)        │
   │      │                                                                      │
   │      ▼                                                                      │
   │  response_worker   ── runs every response mapped to that attack_type:      │
   │      handlers/         block_ip · kill_process · notify                    │
   │      │                                                                      │
   │      ▼                                                                      │
   │  search/es_client  ── mirrors alerts + responses to Elasticsearch ─────────┼──▶ Kibana
   └────────────────────────────────────────────────────────────────────────────┘
```

1. **Django** writes an Apache-format access log (`AccessLogMiddleware`).
2. The **Wazuh agent** tails that log; the **Wazuh manager's** built-in web
   ruleset flags SQLi / XSS / directory traversal / scanners / brute force.
3. Wazuh's **custom integration** (`wazuh-config/integrations/custom-django.py`)
   POSTs each alert to `POST /api/alerts/ingest/` (auth via `X-Wazuh-Secret`).
4. `alerts/hooks.py` **classifies** the alert against `AttackType` rows in the DB
   (keyword match on the Wazuh rule description → `attack_type`, score → `severity`).
   Non-attack noise is dropped.
5. The **response worker** runs every response **mapped** to that attack type
   (block IP via `iptables`, kill process, notify), logging each run in `ResponseAction`.
6. Alerts and responses are mirrored to **Elasticsearch** and visualized in **Kibana**.

> The live classifier is `django-backend/alerts/hooks.py` (DB-driven). The
> top-level `classification-engine/` module is **orphaned** — kept for reference only.

---

## Tech stack

| Layer            | Technology                                             |
|------------------|--------------------------------------------------------|
| Detection        | Wazuh (manager in Docker, agent on host)               |
| Backend / API    | Django 6 + Django REST Framework + SimpleJWT           |
| Database         | PostgreSQL                                             |
| Task queue       | `django-tasks-db` (DB-backed; self-supervising worker) |
| Visualization    | Elasticsearch 8.15 + Kibana 8.15 (standalone, Docker)  |
| Response actions | Python handlers + `iptables`                           |

---

## Services & dependencies we rely on

Everything the system touches at runtime, what it's for, and whether you must
run it:

| Service / component | What it does here | Default port | Required? |
|---------------------|-------------------|--------------|-----------|
| **Wazuh Manager** (Docker) | Runs the web ruleset, raises alerts, runs the custom integration that POSTs to Django | `1514` (agent), `55000` (API) | **Yes** — it's the detection brain |
| **Wazuh Agent** (host) | Tails Django's `django_access.log` and ships events to the manager | — | **Yes** |
| **PostgreSQL** | Primary database (alerts, IP profiles, attack types, responses, task queue) | `5432` | **Yes** |
| **Background task worker** (`django-tasks-db`) | Consumes & executes response tasks (`block_ip`, `kill_process`, `notify`). **Auto-starts inside the Django process** on a daemon thread (`RUN_TASK_WORKER=True`) — no separate process needed | — | **Yes** (built in) |
| **Redis** | Used by the `/api/health/` check and loaded by the Celery app at import. Task execution has migrated to `django-tasks-db`, so Django **still boots without Redis** — but health reports `degraded` and Celery features won't work | `6379` | Recommended |
| **Celery / Flower** | Legacy task layer, **superseded** by `django-tasks-db`. The Celery app is still initialized at startup; you do **not** need to run a Celery worker for responses to fire | `5555` (Flower) | No (legacy) |
| **Elasticsearch** (Docker) | Stores the mirror of alerts + responses for visualization. Separate from the Wazuh indexer | `9201` (host) | For dashboards |
| **Kibana** (Docker) | SOC dashboard UI over Elasticsearch | `5601` | For dashboards |
| **iptables** (host) | The `block_ip` response actually blocks attacker IPs | — | For IP blocking |
| **Docker + Compose** | Runs Wazuh, Elasticsearch and Kibana | — | **Yes** |

> **Workers, explained:** there is **one** worker that matters — the
> `django-tasks-db` DB worker that runs your automated responses. It starts
> automatically with `python manage.py runserver`. To run it as a **separate
> process** instead (e.g. in production), set `RUN_TASK_WORKER=False` in `.env`
> and run `python manage.py db_worker` in its own terminal.

---

## Repository layout

```
automated_incident_response/
├── django-backend/          # the Django project (run from here)
│   ├── manage.py
│   ├── siem_backend/        # settings, urls, middleware
│   ├── alerts/              # Alert model, ingest API, classifier hooks
│   ├── responses/           # ResponseDefinition / AttackResponseMap / admin
│   ├── classification/      # AttackType model (DB-managed attack types)
│   └── search/              # Elasticsearch sync (es_client, es_sync command)
├── response_worker/         # response handlers + actions (block_ip, kill_process, notify)
├── classification-engine/   # ⚠️ orphaned reference module — not used at runtime
├── wazuh-config/            # Wazuh agent localfile + custom integration script
├── kibana/                  # Elasticsearch + Kibana docker-compose + dashboard
├── scripts/attack-simulation/test_attacks.sh   # fire test attacks
├── docs/                    # architecture & how-to notes
├── requirements.txt
└── .env.example
```

---

## Prerequisites

- **Python 3.12+** and `pip`
- **PostgreSQL** running locally
- **Redis** running locally (used by the health check / Celery app — see notes below)
- **Docker** + Docker Compose (for Wazuh and for Kibana/Elasticsearch)
- A working **Wazuh** stack (manager in Docker, agent on the host) — see
  [Wazuh's quickstart](https://documentation.wazuh.com/current/quickstart.html)
- Linux with **iptables** (the `block_ip` response uses it; tested on WSL2)

---

## Run it — baby steps

Follow these in order. Commands assume you start from the project root
`/home/hazem/automated_incident_response`.

### Step 1 — Clone & enter the project

```bash
cd /home/hazem/automated_incident_response
```

### Step 2 — Create a virtualenv and install dependencies

```bash
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 3 — Configure environment variables

Copy the example file and edit the values:

```bash
cp .env.example django-backend/.env
```

Open `django-backend/.env` and set, at minimum:

```ini
DEBUG=True
SECRET_KEY=<generate-a-long-random-string>
ALLOWED_HOSTS=localhost,127.0.0.1

DB_NAME=siem_db
DB_USER=siem_user
DB_PASSWORD=<your-db-password>
DB_HOST=localhost
DB_PORT=5432

# Must match the secret hard-coded in wazuh-config/integrations/custom-django.py
WAZUH_INTEGRATION_SECRET=wazuh-django-secret-key-123

# Elasticsearch (started in Step 8) — leave default if you use kibana/docker-compose.yml
ES_ENABLED=True
ES_URL=http://localhost:9201
```

> ⚠️ Keep `WAZUH_INTEGRATION_SECRET` **identical** to `WAZUH_SECRET` in
> `wazuh-config/integrations/custom-django.py`, or Wazuh's POSTs get a 401.

### Step 4 — Create the PostgreSQL database

```bash
sudo -u postgres psql <<'SQL'
CREATE DATABASE siem_db;
CREATE USER siem_user WITH PASSWORD 'your-db-password';
GRANT ALL PRIVILEGES ON DATABASE siem_db TO siem_user;
ALTER DATABASE siem_db OWNER TO siem_user;
SQL
```

(Use the same name/user/password you put in `.env`.)

### Step 5 — Start Redis

Redis is used by the `/api/health/` check and is loaded by the Celery app at
startup. Start it before running Django:

```bash
# Docker:
docker run -d --name siem-redis -p 6379:6379 redis:7
# …or use a locally installed Redis:
sudo systemctl start redis-server
```

> Django will still boot without Redis, but `/api/health/` will report
> `degraded`. Automated responses do **not** depend on Redis (they use the
> `django-tasks-db` worker).

### Step 6 — Apply migrations & create an admin user

```bash
cd django-backend
python manage.py migrate
python manage.py createsuperuser
```

Migrations seed the default **attack types** and **responses**, so the system is
usable out of the box.

### Step 7 — Run the Django server

```bash
# still inside django-backend/
python manage.py runserver 0.0.0.0:8001
```

- API & admin: <http://localhost:8001/admin/>
- Health check: <http://localhost:8001/api/health/>

> Port **8001** matches the URL the Wazuh integration POSTs to. The background
> **task worker starts automatically** inside this process (`RUN_TASK_WORKER=True`),
> so responses execute without a separate worker — no Celery needed.

### Step 8 — Start Kibana + Elasticsearch (visualization)

From the project root (new terminal):

```bash
docker compose -f kibana/docker-compose.yml up -d
```

- Elasticsearch: <http://localhost:9201> (loopback only)
- Kibana UI: <http://localhost:5601>

Backfill any existing alerts/responses into Elasticsearch:

```bash
cd django-backend
python manage.py es_sync
```

Then import the prebuilt dashboard in Kibana:
**Stack Management → Saved Objects → Import** → `kibana/soc-dashboard.ndjson`.

### Step 9 — Wire Wazuh into the pipeline

The Wazuh **manager** runs in Docker; the **agent** runs on the host machine.

**9a. Register Django's access log with the agent** (so Wazuh reads it):

```bash
sudo bash wazuh-config/install-django-localfile.sh   # idempotent
# make the log world-readable for the wazuh user:
chmod o+r django-backend/logs/django_access.log
sudo systemctl restart wazuh-agent   # or: sudo /var/ossec/bin/wazuh-control restart
```

**9b. Install the custom integration on the Wazuh manager** so alerts reach Django.
Copy `wazuh-config/integrations/custom-django.py` into the manager container's
`/var/ossec/integrations/`, make it executable, and add an `<integration>` block
to the manager's `ossec.conf` referencing it. Confirm inside the script:

- `DJANGO_URL` points at the host where Django runs, on port **8001**
  (e.g. `http://172.18.0.1:8001/api/alerts/ingest/` from inside the container).
- `WAZUH_SECRET` matches `WAZUH_INTEGRATION_SECRET` from your `.env`.

Restart the manager after editing its config.

> 💡 Use `wazuh-config/diagnose-django-detection.sh` to troubleshoot if alerts
> aren't flowing.

### Step 10 — Test the whole pipeline

Fire simulated attacks at the monitored app:

```bash
bash scripts/attack-simulation/test_attacks.sh
```

Wait ~30 seconds, then verify the flow:

1. **Wazuh Dashboard** → Threat Hunting shows the raw alerts.
2. **Django admin** → `/admin/alerts/alert/` shows classified alerts with
   `attack_type` + `severity`.
3. **Django admin** → `/admin/responses/responseaction/` shows the automated
   responses that ran (e.g. blocked IPs).
4. **Kibana** (<http://localhost:5601>) shows the SOC dashboard populated.

✅ If you see classified alerts and executed responses, the pipeline is working.

---

## Day-to-day API reference

Authenticate first (JWT):

```bash
curl -X POST http://localhost:8001/api/auth/token/ \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"<your-pass>"}'
```

| Endpoint                                   | Purpose                              |
|--------------------------------------------|--------------------------------------|
| `POST /api/alerts/ingest/`                 | Wazuh pushes alerts here (secret auth)|
| `GET  /api/alerts/`                         | List / filter classified alerts      |
| `GET  /api/ips/` · `POST /api/ips/{id}/block/` | IP profiles, manual block/unblock |
| `GET  /api/responses/`                     | Executed response actions log        |
| `GET  /api/response-definitions/`          | Configured responses                 |
| `POST /api/response-definitions/{id}/run/` | Run a response manually              |
| `GET  /api/response-handlers/`             | Available handler keys               |
| `GET  /api/health/`                        | Health (DB / Redis / Wazuh)          |

Run a response by hand (e.g. block an IP for 1 hour):

```bash
curl -X POST http://localhost:8001/api/response-definitions/<id>/run/ \
  -H 'Authorization: Bearer <token>' \
  -H 'Content-Type: application/json' \
  -d '{"target":"1.2.3.4","params":{"duration_hours":1}}'
```

---

## Customizing detection & response

Most customization is **dashboard-only, no code**:

- **Add an attack type** → admin → `classification/attacktype/` (key, keywords,
  base score, priority). Next matching alert is classified automatically.
- **Map attack → response** → admin → `responses/attackresponsemap/`.
- **Add a new response action** → write a handler in
  `response_worker/handlers/`, register it with `@register_response('key')`,
  add the module to the import loop in `handlers/__init__.py`, then create a
  `ResponseDefinition` row in admin.

Full guide: [`docs/adding-attacks-and-responses.md`](docs/adding-attacks-and-responses.md).

---

## Troubleshooting

| Symptom | Likely cause / fix |
|---------|--------------------|
| Wazuh POSTs return **401** | `WAZUH_INTEGRATION_SECRET` ≠ `WAZUH_SECRET` in `custom-django.py` |
| No alerts reach Django | Wrong `DJANGO_URL`/port in the integration, or Django not on `0.0.0.0:8001`; run `diagnose-django-detection.sh` |
| Wazuh agent can't read the log | `chmod o+r django-backend/logs/django_access.log` |
| Responses never execute | Task worker disabled — ensure `RUN_TASK_WORKER=True` (default) |
| Kibana empty | Run `python manage.py es_sync` and check `ES_URL=http://localhost:9201` |
| Integration script "requests not found" | The script uses stdlib `urllib` — re-copy the current version into the container |

---

## Further reading

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- [`docs/INSTALLATION.md`](docs/INSTALLATION.md)
- [`docs/adding-attacks-and-responses.md`](docs/adding-attacks-and-responses.md)
</content>
</invoke>
