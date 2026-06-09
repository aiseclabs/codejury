---
id: xml-external-entity
title: XML External Entity
impact: HIGH
tags: [cwe-611, owasp-a03, injection]
triggers: ["etree", "lxml", "xml.dom", "minidom", "sax", "resolve_entities", "DocumentBuilderFactory", "XMLReader"]
---

## XML External Entity

An XML parser that resolves external entities on untrusted input lets an attacker read local files, perform SSRF, or cause DoS via entity expansion. Disable external entity and DTD processing, or use a parser that does so by default such as defusedxml.

### Python
Vulnerable:
```python
from lxml import etree
doc = etree.fromstring(untrusted_xml)   # resolves entities by default
```
Secure:
```python
import defusedxml.ElementTree as ET
doc = ET.fromstring(untrusted_xml)
```
