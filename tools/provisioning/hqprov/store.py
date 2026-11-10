"""Per-unit work directory: resumable step state, a redacting general log, and the mode-0600 secrets file.

  <out>/<unit-id>/
      state.json            step -> {status, at, detail}            (no secrets)
      provision.log         general log, every line passes through the redactor
      boot-N.redacted.log   serial captures with secrets replaced
      identity.json         parsed public identity (MAC, SSID, TLS pub, ...)   (no secrets)
      secrets.json  0600    setup passphrase, QR payload, owner token, owner-file bytes
      label.svg/.png, owner-card.svg/.png  0600 (contain secrets)
      MCTLS.CRT, record.json, ...
"""
import datetime
import json
import os

from . import serialparse


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def jload(path):
    with open(path) as f:
        return json.load(f)


def write_private(path, data):
    """Write bytes/str with mode 0600 from creation (no world-readable window)."""
    mode = "wb" if isinstance(data, bytes) else "w"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, mode) as f:
        f.write(data)
    os.chmod(path, 0o600)


class Unit:
    def __init__(self, workdir):
        self.dir = workdir
        os.makedirs(workdir, mode=0o700, exist_ok=True)
        self.state_path = os.path.join(workdir, "state.json")
        self.secrets_path = os.path.join(workdir, "secrets.json")
        self.state = jload(self.state_path) if os.path.exists(self.state_path) else {"steps": {}}
        self._secrets = jload(self.secrets_path) if os.path.exists(self.secrets_path) else {}

    def p(self, name):
        return os.path.join(self.dir, name)

    # --- secrets ---------------------------------------------------------------------------------
    def secrets(self):
        return dict(self._secrets)

    def set_secret(self, k, v):
        self._secrets[k] = v
        write_private(self.secrets_path, json.dumps(self._secrets, indent=2))

    def secret_strings(self):
        """Every string that must never reach a general log."""
        out = []
        for k, v in self._secrets.items():
            if isinstance(v, str) and len(v) >= 8:
                out.append(v)
        return out

    def redact(self, text):
        return serialparse.redact(text, self.secret_strings())

    # --- log / state -----------------------------------------------------------------------------
    def log(self, msg):
        line = f"{now()} {self.redact(msg)}"
        print(line, flush=True)
        with open(self.p("provision.log"), "a") as f:
            f.write(line + "\n")

    def save_state(self):
        tmp = self.state_path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.state, f, indent=2, sort_keys=True)
        os.replace(tmp, self.state_path)

    def done(self, step):
        return self.state["steps"].get(step, {}).get("status") == "ok"

    def mark(self, step, status, detail=""):
        self.state["steps"][step] = {"status": status, "at": now(), "detail": self.redact(str(detail))}
        self.save_state()

    def save_public(self, name, obj):
        with open(self.p(name), "w") as f:
            json.dump(obj, f, indent=2, sort_keys=True)

    def save_redacted_log(self, name, raw_text):
        with open(self.p(name), "w") as f:
            f.write(self.redact(raw_text))
