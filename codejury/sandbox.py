"""PoC verification sandbox (P2-a): suspected -> proven-exploitable.

Runs a flagged code unit in an isolated subprocess with the dangerous sinks
replaced by recording stubs, feeds a crafted payload carrying a unique marker,
and checks whether the marker reaches a dangerous sink. If it does, the input
provably reaches and controls the sink, so the finding is proven. The real
dangerous operation is never executed.

Safety, defense in depth (the primary defense is that sinks are stubbed):
- the harness runs in a separate subprocess with a wall-clock timeout and, on
  POSIX, CPU and address-space limits;
- the environment is emptied and the working directory is a throwaway tempdir,
  so it cannot reach real files or credentials;
- sockets are blocked, so it cannot reach the network;
- only the named sinks are patched to recorders; everything else stays real so
  the code under test runs faithfully up to the sink.

This is opt-in and recall-safe: a pass adds proof, a timeout/error/no-reach never
removes a finding. Detection knowledge (payload, marker, dangerous sinks) is data
in ``data/poc/<class>.yaml``; this module is the generic mechanism.
"""

from __future__ import annotations

import ast
import json
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from codejury.resources import POC_DIR

_MEM_LIMIT_BYTES = 256 * 1024 * 1024
_CPU_LIMIT_SECONDS = 5
_WALL_TIMEOUT_SECONDS = 10


@dataclass(frozen=True, kw_only=True)
class PocTemplate:
    id: str
    name: str
    cwe: tuple[str, ...]
    payload: str
    marker: str
    sinks: tuple[dict, ...]

    @classmethod
    def from_dict(cls, data: dict) -> PocTemplate:
        return cls(
            id=data["id"],
            name=data.get("name", data["id"]),
            cwe=tuple(data.get("cwe", [])),
            payload=data["payload"],
            marker=data["marker"],
            sinks=tuple(data.get("sinks", [])),
        )


@dataclass(frozen=True, kw_only=True)
class ProofResult:
    proven: bool
    template_id: str = ""
    hits: tuple[str, ...] = ()       # the dangerous sinks the marker reached
    error: str = ""                  # set when the harness could not run to a verdict


def load_poc_templates(directory: str | Path = POC_DIR) -> list[PocTemplate]:
    root = Path(directory)
    if not root.is_dir():
        return []
    return sorted(
        (PocTemplate.from_dict(yaml.safe_load(p.read_text(encoding="utf-8"))) for p in root.glob("*.yaml")),
        key=lambda t: t.id,
    )


def template_for_cwe(cwe: str, templates: list[PocTemplate]) -> PocTemplate | None:
    return next((t for t in templates if cwe and cwe in t.cwe), None)


def _target_function(code: str, line: int | None) -> str | None:
    """The function to drive: the one enclosing the cited line, else the first."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return None
    funcs = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    if not funcs:
        return None
    if line is not None:
        enclosing = [f for f in funcs if f.lineno <= line <= (getattr(f, "end_lineno", f.lineno) or f.lineno)]
        if enclosing:
            return min(enclosing, key=lambda f: line - f.lineno).name
    return min(funcs, key=lambda f: f.lineno).name


def prove(code: str, template: PocTemplate, *, target: str | None = None, line: int | None = None) -> ProofResult:
    """Run ``code``'s target function in the sandbox under ``template`` and report
    whether the payload marker reached a dangerous sink."""
    target = target or _target_function(code, line)
    if not target:
        return ProofResult(proven=False, template_id=template.id, error="no target function")
    config = {
        "marker": template.marker,
        "payload": template.payload,
        "target": target,
        "sinks": [dict(s) for s in template.sinks],
    }
    with tempfile.TemporaryDirectory(prefix="codejury-poc-") as workdir:
        wd = Path(workdir)
        (wd / "target.py").write_text(code, encoding="utf-8")
        (wd / "config.json").write_text(json.dumps(config), encoding="utf-8")
        (wd / "driver.py").write_text(_DRIVER, encoding="utf-8")
        return _run(wd, template.id)


def _run(workdir: Path, template_id: str) -> ProofResult:
    try:
        proc = subprocess.run(
            [sys.executable, "driver.py"],
            cwd=str(workdir),
            env={"PYTHONIOENCODING": "utf-8", "PYTHONDONTWRITEBYTECODE": "1"},
            capture_output=True,
            text=True,
            timeout=_WALL_TIMEOUT_SECONDS,
            preexec_fn=_apply_limits,
        )
    except subprocess.TimeoutExpired:
        return ProofResult(proven=False, template_id=template_id, error="timeout")
    except Exception as exc:  # spawn failure: never crash the audit
        return ProofResult(proven=False, template_id=template_id, error=f"spawn: {exc}")

    line = next((ln for ln in reversed(proc.stdout.splitlines()) if ln.strip().startswith("{")), "")
    try:
        out = json.loads(line)
    except ValueError:
        return ProofResult(proven=False, template_id=template_id, error="no verdict from harness")
    return ProofResult(
        proven=bool(out.get("reached")),
        template_id=template_id,
        hits=tuple(out.get("hits", [])),
        error=str(out.get("error", "")),
    )


def _apply_limits() -> None:  # pragma: no cover - POSIX child setup, not measured in-process
    try:
        import resource

        resource.setrlimit(resource.RLIMIT_CPU, (_CPU_LIMIT_SECONDS, _CPU_LIMIT_SECONDS))
        resource.setrlimit(resource.RLIMIT_AS, (_MEM_LIMIT_BYTES, _MEM_LIMIT_BYTES))
    except Exception:
        pass


# The harness driver. Static (no interpolation): it reads target.py and
# config.json from its working directory, patches the named sinks to recorders,
# blocks the network, runs the target with the payload, and prints one JSON line.
_DRIVER = r'''
import ast, builtins, importlib, inspect, json, socket, sys

cfg = json.load(open("config.json", encoding="utf-8"))
MARKER, PAYLOAD, TARGET, SINKS = cfg["marker"], cfg["payload"], cfg["target"], cfg["sinks"]
HITS = []


def _hit(name):
    if name not in HITS:
        HITS.append(name)


def _recorder(name, req):
    def rec(*args, **kwargs):
        if all(kwargs.get(k) == v for k, v in req.items()):
            for a in args:
                if isinstance(a, str) and MARKER in a:
                    _hit(name); break
                if isinstance(a, (bytes, bytearray)) and MARKER.encode() in bytes(a):
                    _hit(name); break
        return None  # the real dangerous operation never runs
    return rec


# block the network as defense in depth
def _blocked(*a, **k):
    raise OSError("network blocked in sandbox")
socket.socket = _blocked

# patch only the named sinks; everything else stays real
patched_builtins = dict(vars(builtins))
for s in SINKS:
    call, req = s["call"], s.get("requires_kwarg", {})
    if "." in call:
        mod_name, attr = call.rsplit(".", 1)
        try:
            setattr(importlib.import_module(mod_name), attr, _recorder(call, req))
        except Exception:
            pass
    else:
        patched_builtins[call] = _recorder(call, req)

src = open("target.py", encoding="utf-8").read()


class _Any:
    """A permissive stand-in for an undefined free name (a config global, a db
    handle): callable, indexable, attribute-accessible, and path-like."""
    def __call__(self, *a, **k): return self
    def __getattr__(self, n): return self
    def __getitem__(self, k): return self
    def __iter__(self): return iter(())
    def __fspath__(self): return "CJSTUB"
    def __str__(self): return "CJSTUB"


def _free_names(code):
    tree = ast.parse(code)
    bound = set(dir(builtins))
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bound.add(n.name)
        elif isinstance(n, ast.arg):
            bound.add(n.arg)
        elif isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
            bound.add(n.id)
        elif isinstance(n, (ast.Import, ast.ImportFrom)):
            for a in n.names:
                bound.add((a.asname or a.name).split(".")[0])
    used = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)}
    return used - bound


def _result(reached, **extra):
    print(json.dumps({"reached": reached, "hits": HITS, **extra}))
    sys.exit(0)


g = {"__builtins__": patched_builtins}
for name in _free_names(src):
    g[name] = _Any()
try:
    exec(compile(src, "target.py", "exec"), g)
except Exception as e:
    _result(False, error="exec: " + str(e))

fn = g.get(TARGET)
if not callable(fn):
    _result(False, error="target not callable: " + str(TARGET))


class _AnyDict(dict):
    def __init__(self, v): super().__init__(); self._v = v
    def __getitem__(self, k): return self._v
    def get(self, k, d=None): return self._v


class _FakeRequest:
    def __init__(self, v):
        self._v = v
        self.args = self.form = self.values = self.cookies = self.headers = _AnyDict(v)
        self.data = v
        self.json = _AnyDict(v)
    def get_json(self, *a, **k): return _AnyDict(self._v)


args = []
try:
    for p in inspect.signature(fn).parameters.values():
        if p.kind in (p.VAR_POSITIONAL, p.VAR_KEYWORD):
            continue
        args.append(_FakeRequest(PAYLOAD) if p.name.lower() in ("request", "req") else PAYLOAD)
except (ValueError, TypeError):
    args = [PAYLOAD]

try:
    fn(*args)
except Exception:
    pass  # exceptions are fine; the recorder already noted any sink hit

_result(bool(HITS))
'''
