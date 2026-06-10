"""The shipped diff probe cases: small realistic patches, one per vulnerability class,
plus safe lookalikes that must stay clean. Synthetic and authored here, not third-party,
so they ship publicly. A positive carries an expected category, a safe case carries None.
"""

# each case is a tuple of the name, the expected category or None for a safe negative,
# and the diff text
CASES = [
    # positives, should be caught
    ("sqli", "sql-injection", '''diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -10,3 +10,4 @@ def get_user(name):
-    return None
+    q = "SELECT * FROM users WHERE name = '" + name + "'"
+    return db.execute(q).fetchone()
'''),
    ("cmdi", "command-injection", '''diff --git a/ops.py b/ops.py
--- a/ops.py
+++ b/ops.py
@@ -4,2 +4,3 @@ def ping(host):
-    pass
+    import os
+    os.system("ping -c 1 " + host)
'''),
    ("path-traversal", "path-traversal", '''diff --git a/files.py b/files.py
--- a/files.py
+++ b/files.py
@@ -7,2 +7,3 @@ def download(req):
-    return ""
+    path = req.args.get("file")
+    return open(path).read()
'''),
    ("idor", "insecure-direct-object-reference", '''diff --git a/orders.py b/orders.py
--- a/orders.py
+++ b/orders.py
@@ -12,3 +12,4 @@ def get_order(req):
-    return None
+    oid = req.args.get("id")
+    order = Order.objects.get(id=oid)
+    return jsonify(order.to_dict())
'''),
    ("deserialize", "insecure-deserialization", '''diff --git a/cache.py b/cache.py
--- a/cache.py
+++ b/cache.py
@@ -3,2 +3,3 @@ def load(req):
-    return {}
+    import pickle
+    return pickle.loads(req.get_data())
'''),
    ("jwt", "jwt-validation", '''diff --git a/auth.py b/auth.py
--- a/auth.py
+++ b/auth.py
@@ -8,2 +8,3 @@ def verify(token):
-    raise NotImplementedError
+    import jwt
+    return jwt.decode(token, options={"verify_signature": False})
'''),
    ("ssrf", "server-side-request-forgery", '''diff --git a/fetch.py b/fetch.py
--- a/fetch.py
+++ b/fetch.py
@@ -5,2 +5,3 @@ def preview(req):
-    return ""
+    import requests
+    return requests.get(req.args.get("url")).text
'''),
    ("mass-assignment", "mass-assignment", '''diff --git a/users.py b/users.py
--- a/users.py
+++ b/users.py
@@ -9,2 +9,3 @@ def update_profile(req):
-    pass
+    user = User(**req.get_json())
+    user.save()
'''),
    ("open-redirect", "open-redirect", '''diff --git a/web.py b/web.py
--- a/web.py
+++ b/web.py
@@ -5,2 +5,3 @@ def login_done(req):
-    return ""
+    nxt = req.args.get("next")
+    return redirect(nxt)
'''),
    ("xss", "cross-site-scripting", '''diff --git a/views.py b/views.py
--- a/views.py
+++ b/views.py
@@ -6,2 +6,3 @@ def hello(req):
-    return ""
+    name = req.args.get("name")
+    return make_response("<h1>Hi " + name + "</h1>")
'''),
    ("ssti", "server-side-template-injection", '''diff --git a/render.py b/render.py
--- a/render.py
+++ b/render.py
@@ -7,2 +7,3 @@ def page(req):
-    return ""
+    from flask import render_template_string
+    return render_template_string("Hello " + req.args.get("name"))
'''),
    ("weak-crypto", "insecure-cryptography", '''diff --git a/pw.py b/pw.py
--- a/pw.py
+++ b/pw.py
@@ -3,2 +3,3 @@ def store(password):
-    pass
+    import hashlib
+    db.save(hashlib.md5(password.encode()).hexdigest())
'''),
    ("hardcoded-secret", "hardcoded-secrets", '''diff --git a/client.py b/client.py
--- a/client.py
+++ b/client.py
@@ -1,2 +1,3 @@
 import stripe
+stripe.api_key = "sk_live_EXAMPLE_do_not_use_fake_placeholder_key"
'''),
    ("sqli-js", "sql-injection", '''diff --git a/routes.js b/routes.js
--- a/routes.js
+++ b/routes.js
@@ -8,2 +8,3 @@ app.get('/u', (req, res) => {
-  res.end()
+  const q = "SELECT * FROM users WHERE id = " + req.query.id
+  db.query(q, (e, r) => res.json(r))
'''),
    ("cmdi-js", "command-injection", '''diff --git a/run.js b/run.js
--- a/run.js
+++ b/run.js
@@ -4,2 +4,3 @@ function ping(req) {
-  return
+  const { exec } = require('child_process')
+  exec('ping -c 1 ' + req.query.host, cb)
'''),
    ("path-traversal-go", "path-traversal", '''diff --git a/handler.go b/handler.go
--- a/handler.go
+++ b/handler.go
@@ -10,2 +10,3 @@ func download(w http.ResponseWriter, r *http.Request) {
-\treturn
+\tf, _ := os.Open(r.URL.Query().Get("file"))
+\tio.Copy(w, f)
'''),
    ("sqli-java", "sql-injection", '''diff --git a/Dao.java b/Dao.java
--- a/Dao.java
+++ b/Dao.java
@@ -12,2 +12,3 @@ public User find(String id) {
-    return null;
+    String sql = "SELECT * FROM users WHERE id = " + id;
+    return jdbc.queryForObject(sql, User.class);
'''),

    # negatives, safe patterns that should not be flagged
    ("safe-param-sql", None, '''diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -10,3 +10,4 @@ def get_user(name):
-    return None
+    return db.execute("SELECT * FROM users WHERE name = ?", (name,)).fetchone()
'''),
    ("safe-subprocess", None, '''diff --git a/ops.py b/ops.py
--- a/ops.py
+++ b/ops.py
@@ -4,2 +4,3 @@ def ping(host):
-    pass
+    import subprocess
+    subprocess.run(["ping", "-c", "1", host], shell=False, check=True)
'''),
    ("safe-basename", None, '''diff --git a/files.py b/files.py
--- a/files.py
+++ b/files.py
@@ -7,3 +7,4 @@ def download(req):
-    return ""
+    import os
+    name = os.path.basename(req.args.get("file", ""))
+    return open(os.path.join("/srv/public", name)).read()
'''),
    ("safe-redirect-allowlist", None, '''diff --git a/web.py b/web.py
--- a/web.py
+++ b/web.py
@@ -5,3 +5,5 @@ def go(req):
-    return ""
+    target = req.args.get("next", "/")
+    if target not in {"/", "/home", "/account"}:
+        target = "/"
+    return redirect(target)
'''),
    ("safe-jwt-verified", None, '''diff --git a/auth.py b/auth.py
--- a/auth.py
+++ b/auth.py
@@ -8,2 +8,3 @@ def verify(token):
-    raise NotImplementedError
+    import jwt
+    return jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"])
'''),
    ("safe-param-sql-js", None, '''diff --git a/routes.js b/routes.js
--- a/routes.js
+++ b/routes.js
@@ -8,2 +8,3 @@ app.get('/u', (req, res) => {
-  res.end()
+  db.query("SELECT * FROM users WHERE id = ?", [req.query.id], (e, r) => res.json(r))
'''),
    ("safe-orm", None, '''diff --git a/repo.py b/repo.py
--- a/repo.py
+++ b/repo.py
@@ -6,2 +6,3 @@ def find(name):
-    return None
+    return User.objects.filter(name=name).first()
'''),
    ("safe-constant-cmd", None, '''diff --git a/health.py b/health.py
--- a/health.py
+++ b/health.py
@@ -3,2 +3,3 @@ def disk():
-    pass
+    import subprocess
+    return subprocess.run(["df", "-h"], capture_output=True, text=True).stdout
'''),
    ("safe-md5-etag", None, '''diff --git a/cache.py b/cache.py
--- a/cache.py
+++ b/cache.py
@@ -4,2 +4,3 @@ def etag(content_bytes):
-    return ""
+    import hashlib
+    return hashlib.md5(content_bytes).hexdigest()  # cache key, not security
'''),
    ("safe-ownership-idor", None, '''diff --git a/orders.py b/orders.py
--- a/orders.py
+++ b/orders.py
@@ -12,3 +12,6 @@ def get_order(req):
-    return None
+    order = Order.objects.get(id=req.args.get("id"))
+    if order.user_id != req.user.id:
+        abort(403)
+    return jsonify(order.to_dict())
'''),
]
