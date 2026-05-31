# ARISE Assistant

CLI agentic assistant with:
- model routing/switching (free-tier first)
- local persistent memory
- safe local tools (/calc, /plan)
- enterprise cyber defense guardrails

## Run

```bash
python main.py
```

## Configure

Copy `.env.example` to `.env` and set your provider keys/models.

## Cyber Safety Mode

ARISE is designed for safe enterprise defense, not autonomous attacking. It can review cyber and operations work through a sandbox policy before the model answers.

Useful commands:
- `/guard <action>` reviews a command or operation before use.
- `/cyber <request>` classifies a security request as allowed, approval-required, or blocked.
- `/incident <scenario>` creates a defensive response checklist.
- `/sandbox` shows sandbox and audit settings.

The guard blocks offensive automation, credential theft, malware, DDoS, and destructive production actions. Risky enterprise operations require authorization, dry-run thinking, backups, rollback planning, and human approval.
