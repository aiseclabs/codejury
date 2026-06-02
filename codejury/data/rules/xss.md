---
title: Cross-Site Scripting (XSS)
impact: HIGH
tags: [xss, output-encoding, cwe-79, owasp-a03]
triggers: ["innerHTML", "dangerouslySetInnerHTML", "|safe", "mark_safe", "render_template_string", "v-html", "document.write", "Markup("]
---

## Cross-Site Scripting (XSS)

Untrusted data rendered into HTML without encoding executes as script in the victim's browser. Render data as text (textContent), rely on framework auto-escaping, and never disable it for user data.

### JavaScript
Vulnerable:
```javascript
el.innerHTML = "Hello " + username;
```
Secure:
```javascript
el.textContent = "Hello " + username;
```

### Python (templates)
Vulnerable: `return render_template_string("<div>" + user_input + "</div>")`
Secure: rely on Jinja auto-escaping; never pass `| safe` to user data.
