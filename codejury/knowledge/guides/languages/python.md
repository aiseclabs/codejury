---
id: python
title: Python
kind: language
detect:
  files: ["*.py"]
  manifest: []
  imports: []
entrypoint_files: ["*__main__.py", "*main.py", "*cli.py", "*/cli/*.py", "*/commands/*.py"]
entrypoint_markers: ["argparse", "ArgumentParser", "click.command", "click.group", "@click.command", "@click.group"]
logic_layers: ["*/services/*.py", "*services.py", "*/managers/*.py", "*managers.py", "*/dao/*.py", "*dao.py", "*/repositories/*.py", "*/repository/*.py"]
---
# Python Review Notes

Where untrusted input enters beyond web routes, which the framework guide covers:
CLI such as `argparse` or `click`, scheduled jobs, queue consumers, and any function
fed an external value. Non-HTTP sources matter as much as routes.

## Common Sinks
- deserialization: `pickle.loads`, `yaml.load` without `SafeLoader`, `marshal`
- code execution: `eval`, `exec`, `subprocess(..., shell=True)`, `os.system`
- SQL: a string-built query handed to a DB cursor or ORM `.raw()`/`.extra()`
- XML/XXE: `lxml`/`xml.etree` parsing attacker XML
- filesystem: `open()` / `os.path.join` on a path built from user input
- network: `requests.get(user_url)` and similar, the SSRF sink
- template: rendering user input through a template engine
