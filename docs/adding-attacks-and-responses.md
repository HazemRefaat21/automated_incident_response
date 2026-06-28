# Adding Attack Types & Responses

## Pipeline

1. **Wazuh** is the detection layer — its rules decide something is an attack and
   produce an alert with a `rule.description`, `rule.level`, `srcip`, etc.
2. Wazuh's integration script (`wazuh-config/integrations/custom-django.py`) POSTs
   the alert to `POST /api/alerts/ingest/` (with the `X-Wazuh-Secret` header).
3. `alerts/hooks.py` **classifies** it: matches a keyword in Wazuh's
   `rule.description` → `attack_type`, computes a score → `severity`.
4. `response_worker/executor.py` runs every response **mapped** to that `attack_type`.

> The live classifier is `alerts/hooks.py`, which reads attack types from the DB.
> The `classification-engine/` module is orphaned — editing it does nothing.

## 1. New attack type — dashboard only, no code
Attack types live in the DB (`classification.AttackType`). Add one from the admin —
**no code change, no migration**:

Admin → `/admin/classification/attacktype/` → Add:
- **Key**: `ransomware` (stored on alerts + used in response mappings)
- **Name**: `Ransomware`
- **Keywords**: `["ransomware", "file encryption"]` — lowercase substrings matched
  against Wazuh's `rule.description`. First matching type (by **priority**) wins.
- **Base score**: `0–100` (the Wazuh rule-level bonus is added on top → severity)
- **Priority**: lower = checked first (put specific before generic)
- **Is active**: ✓

That's it — the next matching alert is classified as the new type. Then map it to a
response (section 3).

## 2. New response
1. **Action** — `response_worker/actions/<name>.py`: function doing the real work,
   returns `{'success': bool, 'message': str}`.
2. **Handler** — `response_worker/handlers/<name>.py`:
   ```python
   from response_worker.handlers import register_response

   @register_response('quarantine', label='Quarantine Host')
   def quarantine(alert, params, context):
       result = quarantine_host(alert.source_ip)
       result['target'] = alert.source_ip
       return result
   ```
3. Add the module name to the import loop in `handlers/__init__.py`.
4. Create a **ResponseDefinition** row in admin (`/admin/responses/responsedefinition/`):
   name + handler key (dropdown) + params.

## 3. Map attack → response
Admin → `/admin/responses/attackresponsemap/` → Add: pick **attack type** +
**response**, set **order** (lower runs first), optional **params override** (JSON).
Add multiple rows to chain actions. A response runs only if both the map row and its
ResponseDefinition are active. Each run is logged in `ResponseAction`.

## 4. Run a response manually (no attack needed)
Any response can be triggered by hand — no need for a dedicated endpoint per action.

```
POST /api/response-definitions/<id>/run/
{ "target": "1.2.3.4", "params": { "duration_hours": 1 } }
```

- `target` and `params` are optional (e.g. `kill_process` needs no target).
- Runs the handler immediately and returns its result `{success, message, target}`.
- Logged in `ResponseAction` with `trigger='manual'` and `alert=null` (visible/filterable
  in `/admin/responses/responseaction/`).

> Example — manually block an IP for 1h: POST to the **Block IP (1h)** definition's
> `/run/` with `{"target": "1.2.3.4"}`.
