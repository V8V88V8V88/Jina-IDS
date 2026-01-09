# Jina IDS

Network intrusion detection. Sniffs packets,and  spots attacks.

Built this to learn about IDS internals. It actually works, detects SQL injection, XSS, port scans, the usual stuff. Has an ML component too if you're into that.

## Install

```bash
pip install -r requirements.txt
```

## Run

```bash
# for testing
python main.py --test

# actually monitor traffic (need sudo)
sudo python main.py --no-gui

# with gui
sudo python main.py
```

You'll need root for packet capture. That's just how it works.

## What's in here

- `core/` — packet capture, analysis, detection logic
- `ml/` — xgboost anomaly detection
- `gui/` — pyqt6 dashboard
- `data/rules/` — detection signatures (json)

## Adding rules

Edit `data/rules/default_rules.json`. Format's pretty self-explanatory:

```json
{
  "id": "SQLI-001",
  "pattern": "union.*select",
  "severity": "critical"
}
```

Patterns are regex. Severity can be critical/high/medium/low.

## License

GPL v2
