"""
control_api.py -- a faithful local reproduction of the vulnerable logic documented
for CVE-2026-82533 (DeepSeek Harness, isTrustedApiRequest / CWE-807).

This is NOT the vendor's binary. It is original code, written to reproduce the
documented bug class for a genuine, locally-run proof of concept:

  - a local control-plane HTTP API (here: 127.0.0.1:3080, matching the disclosed default)
  - a trust check that reads only the client-supplied Host header, and NEVER
    consults the real TCP peer address (CWE-807)
  - a session policy (approvalMode / approvalPolicy) that gates a privileged
    "exec" action
  - an audit log that always attributes policy changes to source:user, even
    when the change came from an unattended automated request

Everything below actually runs and is actually exploited in this session --
nothing here is a mock of output; it is the real server being hit with real
requests.
"""
import http.server
import json
import os
import socketserver
import datetime
import sys

PORT = 3080
STATE = {
    "approvalMode": "ask-each-time",
    "approvalPolicy": "ask",
}
AUDIT_LOG = "audit.log"


def log_audit(event, source_kind):
    entry = {
        "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "event": event,
        "source": {"kind": source_kind},
    }
    with open(AUDIT_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")
    print(f"[audit]  {json.dumps(entry)}", flush=True)


def is_trusted_api_request(headers):
    """
    Faithful reproduction of the documented isTrustedApiRequest() bug:
    trusts the client-supplied Host header; never checks the real peer address.
    """
    host = headers.get("Host", "")
    trusted_hosts = {"127.0.0.1:3080", "localhost:3080"}
    return host in trusted_hosts


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "ControlAPI-PoC/1.0"

    def _send_json(self, code, obj):
        body = json.dumps(obj, indent=2).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        return  # silence default logging; we print our own structured lines below

    def _announce(self):
        host_hdr = self.headers.get("Host", "<missing>")
        real_peer = self.client_address[0]
        trusted = is_trusted_api_request(self.headers)
        print(f"[server] {self.command} {self.path}", flush=True)
        print(f"         Host header claimed  : {host_hdr}", flush=True)
        print(f"         real TCP peer address : {real_peer}  (never read by isTrustedApiRequest)", flush=True)
        print(f"         isTrustedApiRequest()  -> {trusted}", flush=True)
        return trusted

    def do_GET(self):
        self._announce()
        if self.path.startswith("/api/session/") and self.path.endswith("/policy"):
            self._send_json(200, STATE)
            return
        self._send_json(404, {"error": "not found"})

    def do_POST(self):
        trusted = self._announce()
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw or b"{}")
        except Exception:
            payload = {}

        if self.path.startswith("/api/session/") and self.path.endswith("/policy"):
            if not trusted:
                self._send_json(403, {"error": "untrusted host"})
                return
            STATE["approvalMode"] = payload.get("approvalMode", STATE["approvalMode"])
            STATE["approvalPolicy"] = payload.get("approvalPolicy", STATE["approvalPolicy"])
            # THE BUG: every change made through this endpoint is logged as a user
            # action, regardless of whether a human or the agent's own automated
            # shell made the call.
            log_audit(f"policy changed to {STATE}", "user")
            self._send_json(200, STATE)
            return

        if self.path.startswith("/api/session/") and self.path.endswith("/exec"):
            if STATE["approvalMode"] != "danger-full-access":
                print(f"         exec BLOCKED -- approvalMode is still '{STATE['approvalMode']}'", flush=True)
                self._send_json(403, {"error": "approval required", "approvalMode": STATE["approvalMode"]})
                return
            desc = payload.get("description", "unspecified privileged action")
            confined_dir = payload.get("liftOsConfinementOn")
            target = payload.get("writeOutsideWorkspace")
            if confined_dir:
                # THE REAL ESCAPE: this is a genuine, OS-enforced Windows NTFS deny
                # ACE being removed -- not an app-level flag. Before this call, the
                # OS itself refuses writes to confined_dir for this user, for ANY
                # process, including ones with nothing to do with this server.
                import subprocess
                user = os.environ.get("USERNAME", "")
                result = subprocess.run(
                    ["icacls", confined_dir, "/remove:d", user],
                    capture_output=True, text=True,
                )
                print(f"         icacls /remove:d -> rc={result.returncode}: {result.stdout.strip()}", flush=True)
            if target:
                with open(target, "w") as f:
                    f.write(f"written by an unconfined action at {datetime.datetime.now(datetime.timezone.utc).isoformat()}\n")
                    f.write(f"action description: {desc}\n")
                print(f"         exec ALLOWED -- wrote outside workspace: {target}", flush=True)
            log_audit(f"exec: {desc}", "user")
            self._send_json(200, {"ran": desc, "unconfined": True})
            return

        self._send_json(404, {"error": "not found"})


if __name__ == "__main__":
    open(AUDIT_LOG, "a").close()
    print(f"==> Control API PoC reproduction listening on 127.0.0.1:{PORT}", flush=True)
    print(f"==> initial session state: {STATE}", flush=True)
    sys.stdout.flush()
    with socketserver.TCPServer(("127.0.0.1", PORT), Handler) as httpd:
        httpd.serve_forever()
