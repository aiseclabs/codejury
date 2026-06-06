"""Shared fixtures for the repo-review engine tests.

The engine tests need a small target repo to scaffold and fan out over. They used
to point at `validation/repo/targets/custody`, but `validation/` is a local-only
probe and is gitignored, so it is absent in CI and the tests failed there. This
builds an equivalent minimal target in tmp instead, so the tests are self-contained.
"""

import pytest

_FLASK_APP = '''
from flask import Flask, request
app = Flask(__name__)

@app.route("/wallets/<wallet_id>", methods=["GET"])
def get_wallet(wallet_id):
    return request.args.get("x", "")

@app.route("/transfers", methods=["POST"])
def create_transfer():
    return "", 201
'''


@pytest.fixture
def custody_repo(tmp_path):
    """A tiny Flask app the scaffold detects and seeds at least one unit from. Named
    `custody` so the workspace lands under `<workspace>/custody`, which the engine
    tests rely on."""
    d = tmp_path / "custody"
    (d / "app" / "services").mkdir(parents=True)
    (d / "app" / "routes.py").write_text(_FLASK_APP)
    (d / "app" / "services" / "wallet.py").write_text(
        "def get_wallet(wid):\n    return {'id': wid}\n")
    (d / "requirements.txt").write_text("Flask==3.0\n")
    return d
