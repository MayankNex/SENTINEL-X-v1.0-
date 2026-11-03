# 🛡️ SENTINEL-X

<p align="center">
  <b>Offline URL risk analysis · Evidence-first reporting · Optional AI explanations</b><br/>
  A privacy-conscious learning project for understanding suspicious URL indicators.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/Streamlit-dashboard-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white" alt="Streamlit"/>
  <img src="https://img.shields.io/badge/Analysis-offline-7C3AED?style=for-the-badge" alt="Offline analysis"/>
  <img src="https://img.shields.io/badge/Status-learning%20project-16A34A?style=for-the-badge" alt="Learning project"/>
</p>

> **Important:** SENTINEL-X is an educational heuristic analyzer, not a certified phishing detector, malware scanner, or guarantee that a website is safe. A low score does not prove trustworthiness.

## ✨ What it does

- Parses and validates HTTP/HTTPS URL input.
- Highlights selected warning indicators such as plain HTTP, IP-literal hosts, URL shorteners, unusual TLDs, long hostnames, and IDN/punycode.
- Produces a bounded 0–100 heuristic score with explanations of detected indicators.
- Exports a JSON report containing the hostname and analysis details, not the submitted path or query string.
- Offers an optional AWS Strands / Amazon Bedrock explanation, disabled by default and gated by explicit consent.

## 🔒 Privacy and safety

- The offline analyzer does **not** visit submitted URLs, resolve DNS, open sockets, execute website content, or scan ports.
- Exported JSON reports omit the submitted URL path and query string.
- The optional AI feature sends the hostname, scheme, score, and findings to AWS only after the user opts in. It may incur AWS charges.
- The AI agent has no tools and must not be treated as an authoritative security verdict.
- Do not submit URLs containing secrets, session tokens, or personal information.
- Do not expose a development Streamlit server publicly. This project does not include production authentication or multi-tenant hardening.

## 🚀 Run locally

Requirements: Python 3.11 or newer.

```bash
git clone https://github.com/MayankNex/SENTINEL-X-v1.0-.git
cd SENTINEL-X-v1.0-
python -m venv .venv
```

Activate the environment:

**Windows PowerShell**
```powershell
.venv\Scripts\Activate.ps1
```

**Linux / macOS**
```bash
source .venv/bin/activate
```

Install and start:

```bash
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

Open the local address printed by Streamlit (normally `http://localhost:8501`).

## 🧪 Tests

```bash
python -m unittest discover -s tests -v
python -m compileall -q app.py analyzer.py ai_agent.py tests
```

GitHub Actions runs these checks on pushes and pull requests to `main`.

## 🧠 Optional AWS AI explanation

The offline analyzer works without AWS. To enable the optional explanation:

1. Install optional dependencies with `python -m pip install -r requirements-ai.txt`.
2. Configure `ENABLE_AWS_AI=1`, `BEDROCK_MODEL_ID`, and `AWS_DEFAULT_REGION` in a private environment.
3. Use an authorized AWS account and an appropriate temporary credential/role where possible.
4. Restart the app and explicitly consent before generating an explanation.

Never commit AWS credentials or place them in source files. Model availability, account eligibility, and charges depend on AWS settings and usage.

## 🧭 How to read the score

The score is a simple sum of selected heuristics, capped at 100. It is not a probability, reputation score, or proof of malicious activity. Legitimate websites can trigger warnings, and malicious websites can evade these checks. Always verify a site through trusted channels.

## 🗂️ Project structure

```text
.
├── analyzer.py          # Offline parsing and heuristic scoring
├── app.py               # Streamlit dashboard
├── ai_agent.py          # Optional AWS-backed explanation
├── requirements.txt     # Core dependencies
├── requirements-ai.txt  # Optional AI dependencies
├── tests/               # Unit tests
└── .github/workflows/   # Automated checks
```

## 📌 Roadmap

- [x] Offline URL parsing and heuristic analysis
- [x] JSON report export
- [x] Unit tests and GitHub Actions checks
- [x] Optional AI explanation with explicit consent
- [ ] Expand test coverage for URL edge cases
- [ ] Improve explainability and configurable heuristics
- [ ] Add reproducible sample datasets for learning

## 📄 License

See the repository's license file for applicable terms.

---

<p align="center"><b>Built by MayankNex · Learn carefully. Build responsibly. 🟣</b></p>
