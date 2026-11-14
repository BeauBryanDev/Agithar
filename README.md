# Aegis Cyber Guard

A SOC assistant that watches the real web traffic of my other projects. Five small detection models score every request, a correlator groups suspicious activity per visitor, and escalated cases go to **Agithar**, an LLM agent that investigates them with read-only tools, writes an incident report and alerts the admin on Telegram.

This is an academic portfolio project, but it runs against real traffic, so it is built carefully. Agithar is **read-only**: it watches, explains and recommends. It never blocks, edits or runs anything on the servers.

## What Agithar does

Agithar is the investigator at the end of the pipeline, built on Claude Sonnet 5.5 with LangGraph. When the correlator escalates a case, Agithar:

1. **Investigates.** It reads the case (sensor scores, sanitized evidence) and decides which lookups it needs: IP reputation (AbuseIPDB, VirusTotal, geolocation, Shodan), its own incident history for that IP, CVEs (a local database plus the live NVD API), ExploitDB metadata (never exploit code), MITRE ATT&CK and OWASP Top 10, Sigma detection rules, detection coverage, sensor health, server status, TLS certificates, login sessions and the book knowledge base.
2. **Decides.** It returns a structured verdict through a strict tool: `confirmed`, `false_positive` or `needs_human`, with a confidence, a MITRE technique, an OWASP category and a summary. Code then enforces the escalation rules, whatever the model said. High severity always needs a human. A medium case below 0.7 confidence needs a human. A false positive below 0.85 confidence becomes `needs_human`, so an uncertain call is never closed quietly. Unknown or revoked MITRE ids are corrected against the ATT&CK index.
3. **Reports.** Two writer models produce a defensive report (evidence, recommended actions) and an exposure report (what is exposed, impact, mitigation). They receive only structured, sanitized findings, never raw log text. A deterministic review sends a weak draft back at most twice, and an unapproved section forces human review.
4. **Alerts.** The report is stored on the incident in PostgreSQL, and a short plain-text alert goes to the admin's Telegram. A confident false positive is closed with no alert, so the admin keeps trusting the pings.

Agithar also runs as a **chat console**. Admins and SOC operators ask questions in any language ("how was Florabelle's traffic in the last hour?", "explain this payload"). Agithar answers from live data: shop traffic read from the log, incidents, sensors and lookups. It knows whether it is talking to the admin or to an operator, and it refuses actions it cannot take.

### A real case

A test scan against one of the protected shops: ten requests to non-existent pages in three seconds, all returning 404.

- The nginx log recorded every request with the real visitor IP, restored from behind Cloudflare.
- The scan detector scored the 10-second window **0.999**, about 11 seconds after the last request.
- The correlator escalated it as a medium case and Agithar investigated: AbuseIPDB 0 reports, VirusTotal 0 detections, five earlier incidents from the same IP, healthy sensor, no payload, no successful response.
- Agithar judged it "probably the admin testing" at confidence 0.75. The code rule made that `needs_human`, so it was not closed quietly. Both reports passed review, the incident was stored, and the admin got the Telegram alert.

## How it works

```
nginx log -> sensors -> correlator -> Agithar -> incident + report + Telegram alert
```

- **Ingestion** (`app/ingestion/`): follows the nginx access log (rotation-safe, resumes where it stopped), restores the real visitor IP behind Cloudflare (the header is trusted only from Cloudflare's ranges), filters to the protected sites and builds 10-second windows per IP. Plain static assets skip the payload model.
- **Sensors** (`app/sensors/`): five models behind one interface. Thresholds come from each model's `metadata.json`.

| Sensor | Model | Detects |
|---|---|---|
| `http_payload_sensor` | TF-IDF + logistic regression | SQL injection, XSS, traversal in request URLs |
| `recon_sensor` | XGBoost | Directory brute force and scans (10 s windows) |
| `log_sentinel` | TextCNN (ONNX) | HDFS log sequence anomalies |
| `net_guard` | CNN1D, 8 classes (ONNX) | Network flow attack classes |
| `netflow_sensor` | Logistic regression | Web-attack flows |

- **Correlator** (`app/correlator/`): 60-second windows per IP, best event per sensor, weighted composite score, severity low, medium or high. A window escalates again only when its severity rises.
- **Dispatcher** (`app/agent/dispatcher.py`): runs cases through the agent graph with a concurrency cap, an hourly cap on LLM runs and a timeout. A case that cannot run still alerts the admin.
- **Prompt-injection defence**: logs are attacker-controlled. All free text is sanitized (Unicode control and bidi characters removed, length caps). Evidence and tool results reach the model as escaped, untrusted data blocks. Tools are allowlisted and read-only, and the alert path is pipeline-only, never a model tool.

## Knowledge base (RAG)

Eight public books (NIST SP 800-61r3 and 800-150, an NSA cloud-logging guide, *The Practice of Network Security Monitoring*, *11 Strategies of a World-Class SOC*, the Debian Reference, *How Linux Works*, *Linux Basics for Hackers*) are split into 1,699 chunks of about 512 tokens. They are embedded with OpenAI `text-embedding-3-small` and stored in Pinecone in three namespaces: `soc`, `linux-admin` and `offensive`. Log and terminal listings are never split. Agithar gets the top 3 passages with book and page citations, wrapped as untrusted data.

### Retrieval evaluation

Golden set: 60 questions (55 in scope, 5 out of scope) with 193 graded chunk labels (2 = answers the question, 1 = partly relevant). Question types are direct, keyword, paraphrase, listing and multi-passage. Run `scripts/eval_retrieval.py`. A run takes about 2 minutes and costs under one cent.

Results (run of 2026-11-14, raw top 10 from Pinecone):

| Metric | Score |
|---|---|
| Hit@1 | 0.855 |
| Hit@3 | 0.982 |
| Answer hit@3 (a grade-2 chunk in the top 3) | 0.891 |
| Hit@5 | 1.000 |
| MRR@10 | 0.920 |
| MAP@10 | 0.852 |
| nDCG@10 | 0.846 |
| Recall@10 | 0.979 |
| Book hit@3 / page hit@3 | 1.000 / 1.000 |

| Namespace | Hit@3 | Answer hit@3 | nDCG@10 |
|---|---|---|---|
| `soc` (30 questions) | 0.967 | 0.967 | 0.874 |
| `linux-admin` (18) | 1.000 | 0.722 | 0.763 |
| `offensive` (7) | 1.000 | 1.000 | 0.939 |

| Question type | Hit@3 | nDCG@10 |
|---|---|---|
| Direct | 1.000 | 0.880 |
| Keyword | 1.000 | 0.869 |
| Listing | 1.000 | 0.995 |
| Paraphrase | 0.909 | 0.748 |
| Multi-passage (2 questions) | 1.000 | 0.520 |

Other findings:

- **What the agent actually sees** (top 3 after removing overlapping passages): hit@3 0.927, answer hit@3 0.782. The de-duplication drops adjacent chunks, which are often the relevant ones, so it costs some accuracy. Tuning it is the next step.
- **Out-of-scope questions** top out at a cosine score of 0.09 to 0.34, while every in-scope question had a relevant hit above 0.39. A minimum score between 0.35 and 0.45 would reject all five negatives without losing a question. Five negatives are too few to set that cutoff yet.
- **Latency**: p50 0.96 s, p95 2.2 s per query (embedding plus search).
- **Caveat**: these numbers are optimistic. The questions were written from the chunks, so they share vocabulary, and the labels come from pooling the same retriever. Harder paraphrased questions and a hybrid BM25 + dense search are planned and will be compared with `--compare`.

## Backend and frontend

- **Backend**: FastAPI, SQLAlchemy and PostgreSQL, DynamoDB for chat history, JWT auth with admin, operator and guest roles, rate limits per real client IP, LangSmith tracing (public visitor chats are not traced).
- **Frontend** (`frontend/`): React 19, Vite, Tailwind 4, TypeScript. Pages: console, dashboard (live server telemetry, live anomalies, shop traffic, detection coverage with an ATT&CK Navigator export), detection feed, incident detail, sensors, CVE lookup, file ingest, profile, user management. The build generates a Content-Security-Policy with hashes.
- **Public demo**: visitors enter as guests (no password, 30-minute token) and get a smaller agent on a cheaper model (GPT-6-luna) with capped tools, plus read-only sensors, CVE lookup and file analysis. Everything is limited per visitor IP and by global daily caps.
- **File analysis**: upload a `.log`, `.txt` or `.csv`, and the sensors analyze it with no LLM. Nothing is stored, executed or unpacked.
- **Tests**: a pytest suite (`arrash/bin/python -m pytest`), offline, with every network call mocked.

## Deployment

One AWS EC2 box next to the shops. The API runs under systemd as its own Unix user with memory limits, behind nginx and Cloudflare. A second nginx log in a fixed format feeds Agithar without touching the shops' own logs. The database is separate from the shops' databases. The frontend is built from `frontend/` and served by Cloudflare Pages.

## Known limits

- The HTTP payload model was trained on a public 2010 dataset and flags some normal shop URLs. The plan is to retrain it with real normal traffic.
- The scan detector relies mostly on the share of 404 responses. A site that answers unknown pages with a redirect or a 200 hides a scan from it, and a burst that crosses a 10-second window boundary is split.
- Only the payload and scan sensors have a live feed. The other three work on pasted, uploaded or pushed input.
- The nginx log has no request bodies, so attacks inside POST bodies are not seen.
- Metrics in the model folders come from public benchmarks and are optimistic.

## Run locally

```
python3.12 -m venv arrash && arrash/bin/pip install -r requirements.txt
arrash/bin/uvicorn app.main:app --reload --env-file .env
cd frontend && npm install && npm run dev
```

Settings are read from `.env` (`JWT_SECRET_KEY` of at least 32 characters, `DATABASE_URL`, `CORS_ORIGINS`, API keys). Model files and data are not in git. See `models/` and `data/` in the settings.

## Origin

The project started as a QLoRA fine-tune of Qwen2.5-7B, which lives in a ZeroGPU Space on Hugging Face (`beaunix/aegis-cyber-guard`). It is not part of the application: a 7B model is too small to lead the system.
