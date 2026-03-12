# ThreatTrace

[![Threat Intelligence Demo](https://img.shields.io/badge/ThreatTrace-Live%20Demo-orange)](https://threattrace-raou.onrender.com/)
![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-Framework-009688)
![Docker](https://img.shields.io/badge/Docker-Supported-2496ED)
![License](https://img.shields.io/badge/License-MIT-green)
![OSINT](https://img.shields.io/badge/Category-OSINT-red)


**ThreatTrace** is an **OSINT-based Threat Intelligence Investigation Platform** that discovers malicious infrastructure, correlates intelligence, scores risk, and visualizes threat campaigns.

The platform automates multi-source OSINT investigations and helps analysts understand relationships between domains, URLs, IPs, and infrastructure.

Inspired by tools like SpiderFoot and enterprise threat intelligence platforms.

---

# Dashboard

ThreatTrace provides a **web-based investigation dashboard** for exploring threat infrastructure.

Features include:

- Infrastructure graph visualization
- Campaign timeline analysis
- Risk scoring
- Multi-source OSINT enrichment
- Automated investigation engine

Example workflow:

1. Enter a domain / URL / hash
2. Run investigation
3. Explore graph relationships
4. Analyze timeline and campaign patterns
5. Export intelligence report

---

# Key Features

| Feature | Description |
|------|-------------|
| Threat Infrastructure Graph | Visualize Domain → URL → Payload Hash relationships |
| Campaign Timeline | Analyze campaign activity over time |
| Modular OSINT Engine | URLHaus, crt.sh, Passive DNS, GitHub modules |
| Automated Investigation | Multi-module scanning engine |
| Risk Scoring | Score infrastructure risk from 0–100 |
| Intelligence Correlation | Detect shared infrastructure and payloads |
| Pattern Detection | Identify suspicious patterns (DGA, infra reuse) |
| Monitoring | Track domains and receive alerts |
| Investigation Reports | Export results as JSON, PDF, Markdown |

---

# Architecture

ThreatTrace is designed using a **modular OSINT investigation architecture**.

Core components include:

- **Scan Engine** — orchestrates OSINT modules  
- **Threat Graph Builder** — maps infrastructure relationships  
- **Timeline Analyzer** — detects campaign activity patterns  
- **Risk Scoring Engine** — calculates threat level  
- **Intel Correlator** — identifies shared indicators  
- **Monitoring Service** — tracks domains over time  

---

# Quick Start

Clone the repository:

```bash
git clone https://github.com/carlos-rezende/ThreatTrace.git
cd ThreatTrace

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
│
├── app/
│   ├── main.py
│   ├── core/            # configuration & rate limiting
│   ├── api/             # REST endpoints
│   ├── clients/         # external API clients
│   ├── modules/         # OSINT modules
│   ├── engine/          # investigation engine
│   ├── graph/           # infrastructure graph builder
│   ├── services/        # timeline, risk scoring, correlation
│   ├── monitoring/      # monitoring service
│   ├── reports/         # investigation reports
│   ├── schemas/         # Pydantic models
│   └── utils/           # helpers
│
├── static/              # web dashboard
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

## Environment

```env
| Variable         | Description                     |
| ---------------- | ------------------------------- |
| URLHAUS_AUTH_KEY | Required API key                |
| GITHUB_TOKEN     | Optional GitHub OSINT module    |
| PORT             | Application port (default 8090) |

```

## Running with Docker

```bash
docker-compose up -d
```

```Then open:
http://localhost:8090
```
## Roadmap

Planned improvements:

- Threat actor clustering
- Infrastructure fingerprinting
- Threat feed aggregation
- Historical attack surface analysis
- Graph-based intelligence correlation

---

## Contributing

Contributions are welcome.

Steps:

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Open a Pull Request

---

## Security Notice

ThreatTrace uses **public OSINT sources**.

The project is intended for:

- Cybersecurity research
- Threat intelligence analysis
- Educational use

---

## License

MIT License

---

## Author

**Carlos Rezende**

Cybersecurity enthusiast building **OSINT and threat intelligence tools**.

---

## Portfolio Value

This project demonstrates:

- OSINT automation
- Threat Intelligence tooling
- FastAPI backend architecture
- Cybersecurity data analysis
- Graph-based infrastructure mapping
