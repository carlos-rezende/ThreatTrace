# ThreatTrace

> **Threat Intelligence Investigation Platform** — OSINT-based tool that discovers threat infrastructure, correlates intelligence, scores risk, and visualizes campaigns.

Inspired by SpiderFoot and commercial platforms like Recorded Future. Suitable for cybersecurity portfolios.

## Features

| Feature | Description |
|---------|-------------|
| **Threat Graph** | Domain → URL → Payload Hash relationships (D3.js/Cytoscape compatible) |
| **Timeline Analysis** | Campaign activity over time |
| **Modular OSINT** | URLHaus, crt.sh, Passive DNS, GitHub modules |
| **Investigation Engine** | Automated multi-module scanning |
| **Risk Scoring** | 0-100 score (low/medium/high) |
| **Intel Correlation** | Shared infrastructure, payloads, families |
| **Pattern Detection** | DGA, infrastructure reuse, multi-campaign |
| **Monitoring** | Track domains, webhook/email alerts |
| **Reports** | JSON, PDF, Markdown |

## Quick Start

```bash
python -m venv venv
.\venv\Scripts\activate  # Windows
pip install -r requirements.txt
# Set URLHAUS_AUTH_KEY in .env (https://auth.abuse.ch/)
uvicorn app.main:app --reload --port 8090
```

- **Dashboard**: http://localhost:8090/
- **API Docs**: http://localhost:8090/docs

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/domain/{domain}` | Domain lookup |
| GET | `/api/url/{url}` | URL lookup |
| GET | `/api/hash/{hash}` | Hash lookup |
| GET | `/api/campaigns/{domain}` | Campaigns |
| GET | `/api/graph/{domain}` | Infrastructure graph (D3/Cytoscape) |
| GET | `/api/timeline/{domain}` | Campaign timeline |
| GET | `/api/risk/{domain}` | Risk score |
| GET | `/api/patterns/{domain}` | Pattern detection |
| POST | `/api/investigate` | Full OSINT investigation |
| POST | `/api/monitor` | Add to monitoring |
| GET | `/api/modules` | List OSINT modules |

## Project Structure

```
ThreatTrace/
├── app/
│   ├── main.py
│   ├── core/           # config, limiter
│   ├── api/            # routes
│   ├── clients/        # URLHaus client
│   ├── modules/        # OSINT modules (urlhaus, crtsh, github, passive_dns)
│   ├── engine/         # Scan engine, module runner
│   ├── graph/          # Graph builder, models, service
│   ├── services/       # Campaign analyzer, timeline, risk, correlation, patterns
│   ├── monitoring/     # Monitor service
│   ├── reports/        # Investigation reports
│   ├── schemas/        # Pydantic schemas
│   └── utils/          # Report generator
├── static/             # Dashboard (Chart.js)
├── Dockerfile
└── docker-compose.yml
```

## Environment

```env
URLHAUS_AUTH_KEY=your-key    # Required
GITHUB_TOKEN=optional        # For GitHub module
PORT=8090
```

## Docker

```bash
docker-compose up -d
```

## License

MIT
