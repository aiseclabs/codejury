---
id: xml-external-entity
title: XML External Entity
lens: xml-external-entity
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
parser = etree.XMLParser(resolve_entities=True, load_dtd=True, no_network=False)
doc = etree.fromstring(untrusted_xml, parser)   # external entities resolved
```
Secure:
```python
import defusedxml.ElementTree as ET
doc = ET.fromstring(untrusted_xml)
```

### Not a Finding

Parsing with defusedxml, or with a parser that disables DTD and external entities such as `etree.XMLParser(resolve_entities=False, no_network=True)`, is not a finding. Plain XML parsing is a finding only when external entity resolution is actually enabled.
