# Aegis Cyber Guard

A SOC-assistant AI agent. Small local detectors score security events, a correlator groups them per IP and time window, and a master LLM agent ("Agithar", Claude via the Anthropic API) makes the final call on escalated cases. This is an academic portfolio project, built to production-style standards because it is meant to ingest real logs from the my other e-commerce projects. It is still work in progress.

## Architecture

```
ingestion (planned) -> sensors -> correlator -> agent (planned) -> API / PostgreSQL
```

- **Sensors** (`app/sensors/`): five models behind a common `Sensor` / `SensorResult` interface, loaded by a registry that tolerates individual load failures.
- **Correlator** (`app/correlator/`): keeps anomalous events in fixed 60 s windows per IP, one best event per sensor, computes a weighted composite score and escalates by severity. Weak sensors add to the score but cannot escalate alone.
- **Master agent** (`app/agent/`, in progress): LangGraph ReAct loop with RAG and threat-intel tools. It triages escalated cases, raises a human alert, stores the incident, or lets the case pass.
- **API** (`app/api/`): FastAPI, sync routes, JWT auth (bcrypt, HS256), in-memory failure rate limiting, strict security headers.
- **Storage**: PostgreSQL via SQLAlchemy for users, incidents, IOCs and actions taken.

## Sensors

| Sensor | Model | Detects | Runtime |
|---|---|---|---|
| `log_sentinel` | TextCNN | HDFS log sequence anomalies | ONNX |
| `net_guard` | CNN1D, 8 classes | Network flow attack classes (CICIDS2017) | ONNX |
| `http_payload_sensor` | TF-IDF + logistic regression | Malicious HTTP request payloads | joblib |
| `netflow_sensor` | Logistic regression | Web-attack flows (CIC-IDS-2017) | joblib |
| `recon_sensor` | XGBoost | Web directory brute force / scans (MITRE T1595) | joblib |

Thresholds, class names and features are read from each model's `metadata.json`. Metrics come from public benchmarks and are optimistic: validate on real logs before trusting any threshold. Per-model limits are documented in `CLAUDE.md`.

## Incidents and IOCs

Escalated cases are stored as incidents. Ingestion attaches a sanitized `EventContext` to each event (HTTP method, path with the query string removed, SHA-256 of the user agent, status code). Raw URLs, bodies and user agents are never logged or stored. IOCs (IP, URL path, user agent hash) are extracted from the evidence.

Endpoints under `/api` (authenticated):

- `GET /incidents/by-ip/{ip}`, `GET /incidents/by-severity/{severity}`, `GET /incidents/{case_key}`
- `/users/*` for login and account management; `/health` and `/health/ready` are public.

## Status

Implemented: sensors, correlator, users and auth, incident storage and read API, OWASP Top 10 2025 lookup. Not yet built: ingestion (log parsing, CICFlowMeter mapping), the agent graph and tools, the RAG indexer and retriever, and most external service clients. No migrations exist yet. There is no test suite.

## Run

```
python3.12 -m venv arrash && arrash/bin/pip install -r requirements.txt
arrash/bin/uvicorn app.main:app --reload
cd frontend && npm install && npm run dev
```

Configuration is read from `.env` (model paths, `JWT_SECRET_KEY` of at least 32 characters, `DATABASE_URL`, `CORS_ORIGINS`). Model files are not all tracked in git (`*.onnx` is ignored).

## Stack

Python 3.12, FastAPI, SQLAlchemy, ONNX Runtime, scikit-learn, XGBoost, LangGraph, ChromaDB, Anthropic API; React 19, Vite, Tailwind 4 and TypeScript for the frontend.

## Origin

The project started as a QLoRA fine-tune of Qwen2.5-7B. It has grown well beyond that. The Qwen model is not part of the application and lives in a ZeroGPU Space on Hugging Face: `beaunix/aegis-cyber-guard`.
