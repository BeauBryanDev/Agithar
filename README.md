# Aegis Cyber Guard

A SOC assistant. It reads the real web logs of my other e-commerce projects, scores every request with five small detection models, groups suspicious activity per IP, and hands escalated cases to an LLM agent ("Agithar") that investigates them with lookup tools, writes a report and alerts the admin on Telegram.

This is an academic portfolio project, built carefully because it runs against real traffic. It is read-only: Agithar watches and advises, it never blocks or changes anything.

## How it works

```
nginx log -> sensors -> correlator -> agent -> incident + report + Telegram alert
```

- **Ingestion** (`app/ingestion/`): follows the nginx access log (rotation-safe, resumes where it stopped), restores the real visitor IP behind Cloudflare, builds per-IP 10 s windows. Starts in log-only mode: it scores and logs, raises nothing.
- **Sensors** (`app/sensors/`): five models behind one interface. Thresholds come from each model's `metadata.json`.

| Sensor | Model | Detects |
|---|---|---|
| `http_payload_sensor` | TF-IDF + logistic regression | SQL injection, XSS, traversal in request URLs |
| `recon_sensor` | XGBoost | Directory brute force and scans (10 s windows) |
| `log_sentinel` | TextCNN (ONNX) | HDFS log sequence anomalies |
| `net_guard` | CNN1D, 8 classes (ONNX) | Network flow attack classes |
| `netflow_sensor` | Logistic regression | Web-attack flows |

- **Correlator** (`app/correlator/`): 60 s windows per IP, best event per sensor, weighted score, severity low / medium / high.
- **Agent** (`app/agent/`): LangGraph. A master LLM investigates a case with read-only tools, then two writers produce a defensive and an exposure report, a deterministic check reviews them (at most two send-backs), and the result is stored and alerted. Clear false positives are closed quietly.
- **Tools**: local CVE database plus live NVD, MITRE ATT&CK and OWASP lookups, AbuseIPDB, VirusTotal, Shodan, ExploitDB metadata (no exploit code), server and sensor health, shop traffic from the log, and a book knowledge base in Pinecone (SOC, Linux admin, offensive basics).
- **Chat console**: operators and admins talk to Agithar and get answers from live data. The agent knows whether it is talking to an admin or an operator.
- **Public demo**: visitors enter as guests (no password, 30-minute token) and get a smaller agent on a cheaper model with capped tools, plus read-only sensors, CVE lookup and file analysis. Everything is limited per visitor IP.
- **File analysis**: upload a `.log`, `.txt` or `.csv`; the sensors analyze it. Nothing is stored or executed.

## Backend and frontend

- **Backend**: FastAPI, SQLAlchemy and PostgreSQL, JWT auth with admin / operator / guest roles, rate limits, input sanitizing against prompt injection hidden in logs.
- **Frontend** (`frontend/`): React 19, Vite, Tailwind 4, TypeScript. Pages: console, dashboard, detection feed, incident detail, sensors, CVE lookup, ingest, profile, user management. The build generates a Content-Security-Policy with hashes.

## Deployment

One EC2 box next to the shops: the API runs under systemd as its own Unix user with memory limits, behind nginx and Cloudflare. The database is a separate database on the existing RDS instance. The frontend is built from `frontend/` and served by Cloudflare Pages.

## Status and known limits

- Running on real traffic in log-only mode while I measure false alarms.
- The HTTP payload model was trained on a public 2010 dataset and flags some normal shop URLs. The plan is to retrain it with real normal traffic.
- Only the payload and recon sensors have a live feed. The other three work on pasted or uploaded input.
- The nginx log has no request bodies, so attacks inside POST bodies are not seen.
- Metrics in the model folders come from public benchmarks and are optimistic.

## Run locally

```
python3.12 -m venv arrash && arrash/bin/pip install -r requirements.txt
arrash/bin/uvicorn app.main:app --reload
cd frontend && npm install && npm run dev
```

Settings are read from `.env` (`JWT_SECRET_KEY` of at least 32 characters, `DATABASE_URL`, `CORS_ORIGINS`, API keys). Model files and data are not in git (`*.onnx` is ignored); see `models/` and `data/` in the settings.

## Origin

The project started as a QLoRA fine-tune of Qwen2.5-7B, which lives in a ZeroGPU Space on Hugging Face (`beaunix/aegis-cyber-guard`). It is not part of the application.
