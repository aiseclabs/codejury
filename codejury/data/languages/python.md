---
id: python
title: Python
kind: language
detect:
  files: ["*.py"]
  manifest: []
  imports: []
---
# Python review notes

Where untrusted input enters (beyond web routes, which the framework guide covers):
CLI (`argparse`/`click`), scheduled jobs, queue consumers, and any function fed an
external value. Non-HTTP sources matter as much as routes:

- deserialization: `pickle.loads`, `yaml.load` without `SafeLoader`, `marshal`
- code execution: `eval`, `exec`, `subprocess(..., shell=True)`, `os.system`
- XML/XXE: `lxml`/`xml.etree` parsing attacker XML
- filesystem: `open()` / `os.path.join` on a path built from user input
- network: `requests.get(user_url)` and friends (SSRF).

Common sinks: string-built SQL handed to a DB cursor or ORM `.raw()`/`.extra()`,
a shell command, `eval`/`exec`, a user-controlled file path, a fetch of a
user-controlled URL, and template rendering of user input.
