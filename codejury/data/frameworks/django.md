---
id: django
title: Django
kind: framework
detect:
  files: ["*urls.py", "manage.py", "*settings.py"]
  manifest: ["django"]
  imports: ["from django", "import django"]
entrypoint_files: ["*urls.py"]
---
# Django review notes

## Entrypoints
- Routes live in `urls.py`: `path()` / `re_path()` map a URL to a view.
  `include('app.urls')` mounts a sub-urlconf and the URL prefix accumulates.
  Class-based views are wired as `SomeView.as_view()`.
- Also: Django REST Framework viewsets/routers/serializers, management commands,
  signals, and middleware.

## Authorization / IDOR
- Auth is enforced by decorators (`@login_required`), DRF permission classes, or
  middleware. Note where it is and where it is missing.
- Classic IDOR shape: `Model.objects.get(pk=<user input>)` (or `filter(id=...)`)
  with no owner/tenant scoping, then returned to the caller. Inspect every object
  fetch keyed by a user-supplied id.

## Common sinks / gotchas
- SQL: `.raw()`, `.extra()`, `RawSQL`, or string-built SQL via `connection.cursor()`.
- Templates: `mark_safe`, `|safe`, `format_html` on unescaped user input, autoescape off.
- `pickle` / `yaml.load` on a cookie or upload, `DEBUG=True` leaking internals,
  a hardcoded `SECRET_KEY`.
