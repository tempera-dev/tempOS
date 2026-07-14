#!/usr/bin/env python3
"""Exercise beater-osd-http's token-gated memory context surface."""

from __future__ import annotations

import argparse
import http.client
import json
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parent.parent
TOKEN = "beateros-http-memory-context-smoke-token"
SESSION_ID = "http-memory-context-smoke-session"
MEMORY_SCOPE = "session:http-memory-context-smoke"


def free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def start_server(root: Path, token_file: Path, port: int) -> subprocess.Popen[str]:
    return subprocess.Popen(
        [
            "cargo",
            "run",
            "-q",
            "-p",
            "beater-osd-http",
            "--",
            "serve",
            "--root",
            str(root),
            "--token-file",
            str(token_file),
            "--bind",
            f"127.0.0.1:{port}",
            "--once",
        ],
        cwd=REPO_ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def request(
    port: int,
    path: str,
    body: dict[str, Any],
    *,
    token: str | None,
) -> tuple[int, dict[str, Any]]:
    headers = {"content-type": "application/json"}
    if token is not None:
        headers["authorization"] = f"Bearer {token}"
    encoded = json.dumps(body).encode("utf-8")
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=45)
    try:
        connection.request("POST", path, body=encoded, headers=headers)
        response = connection.getresponse()
        payload = json.loads(response.read().decode("utf-8"))
        return response.status, payload
    finally:
        connection.close()


def wait_server(process: subprocess.Popen[str]) -> None:
    stdout, stderr = process.communicate(timeout=30)
    if process.returncode != 0:
        raise RuntimeError(
            f"beater-osd-http exited {process.returncode}\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
        )


def stop_server(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate(timeout=5)


def one_shot_request(
    root: Path,
    token_file: Path,
    path: str,
    body: dict[str, Any],
    *,
    token: str | None,
) -> tuple[int, dict[str, Any]]:
    port = free_loopback_port()
    server = start_server(root, token_file, port)
    try:
        deadline = time.monotonic() + 15
        last_error: Exception | None = None
        while time.monotonic() < deadline:
            if server.poll() is not None:
                break
            try:
                response = request(port, path, body, token=token)
                wait_server(server)
                return response
            except (ConnectionRefusedError, TimeoutError, OSError) as error:
                last_error = error
                time.sleep(0.1)
        if server.poll() is not None:
            stdout, stderr = server.communicate(timeout=1)
            raise RuntimeError(
                "beater-osd-http exited before request; "
                f"return={server.returncode}\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
            )
        raise RuntimeError(f"beater-osd-http did not accept request: {last_error}")
    except Exception:
        stop_server(server)
        raise


def bootstrap_body() -> dict[str, Any]:
    return {
        "session_id": SESSION_ID,
        "session": {
            "session_id": SESSION_ID,
            "agent_id": "agent:http-memory-context-smoke",
            "workspace_id": "workspace:http-memory-context-smoke",
            "goal": "select policy-safe memory context",
            "memory_scope": MEMORY_SCOPE,
        },
        "grants": [],
        "steps": [],
    }


def memory_record(
    memory_id: str,
    *,
    sensitivity: str,
    source_classes: list[str],
    source_taint: list[str] | None = None,
    source_event_id: str = SESSION_ID,
    expires_at: str | None = None,
    access_policy: str = "session",
) -> dict[str, Any]:
    return {
        "session_id": SESSION_ID,
        "memory": {
            "memory_id": memory_id,
            "source_event_id": source_event_id,
            "source_digest": f"sha256:{SESSION_ID}",
            "writer": "writer:trusted",
            "created_at": "2026-01-01T00:00:00Z",
            "scope": MEMORY_SCOPE,
            "kind": "summary",
            "content_ref": f"memory://{memory_id}",
            "summary": f"summary for {memory_id}",
            "confidence_basis_points": 9000,
            "sensitivity": sensitivity,
            "source_taint": source_taint or [],
            "source_data_classes": source_classes,
            "expires_at": expires_at,
            "access_policy": access_policy,
        },
    }


def context_body(session_id: str = SESSION_ID, scope: str | None = None) -> dict[str, Any]:
    context: dict[str, Any] = {
        "max_items": 4,
        "max_rejections": 4,
        "allowed_sensitivities": ["public", "internal"],
        "denied_source_taint": ["untrusted_web"],
        "denied_source_data_classes": ["secret"],
        "allowed_access_policies": ["session"],
        "trusted_writers": ["writer:trusted"],
    }
    if scope is not None:
        context["scope"] = scope
    return {"session_id": session_id, "context": context}


def run_smoke(root: Path, *, as_json: bool) -> int:
    token_file = root / "token"
    token_file.write_text(TOKEN, encoding="utf-8")

    status, payload = one_shot_request(
        root,
        token_file,
        "/v1/runtime/bundles",
        bootstrap_body(),
        token=TOKEN,
    )
    if status != 200:
        raise RuntimeError(f"expected session bootstrap 200, got {status}: {payload}")
    if payload.get("session_id") != SESSION_ID or not payload.get("created_session"):
        raise RuntimeError(f"unexpected bootstrap response: {payload}")

    record_path = f"/v1/sessions/{SESSION_ID}/memory/records"
    unanchored_status, unanchored_payload = one_shot_request(
        root,
        token_file,
        record_path,
        memory_record(
            "unanchored-context",
            sensitivity="internal",
            source_classes=["internal"],
            source_event_id="missing-source-event",
        ),
        token=TOKEN,
    )
    if unanchored_status != 403:
        raise RuntimeError(
            f"expected 403 for unanchored memory source, got {unanchored_status}: {unanchored_payload}"
        )

    for body in [
        memory_record("trusted-context", sensitivity="internal", source_classes=["internal"]),
        memory_record("secret-context", sensitivity="secret", source_classes=["secret"]),
        memory_record(
            "expired-context",
            sensitivity="internal",
            source_classes=["internal"],
            expires_at="2025-01-01T00:00:00Z",
        ),
        memory_record(
            "poisoned-context",
            sensitivity="internal",
            source_classes=["internal"],
            source_taint=["untrusted_web"],
        ),
        memory_record(
            "policy-disallowed-context",
            sensitivity="internal",
            source_classes=["internal"],
            access_policy="operator-only",
        ),
    ]:
        record_status, record_payload = one_shot_request(
            root, token_file, record_path, body, token=TOKEN
        )
        if record_status != 201:
            raise RuntimeError(
                f"expected memory record 201, got {record_status}: {record_payload}"
            )
        if record_payload.get("memory_id") != body["memory"]["memory_id"]:
            raise RuntimeError(f"unexpected memory record response: {record_payload}")

    select_path = f"/v1/sessions/{SESSION_ID}/memory/context/select"
    unauth_status, unauth_payload = one_shot_request(
        root, token_file, select_path, context_body(), token=None
    )
    if unauth_status != 401:
        raise RuntimeError(f"expected 401 without token, got {unauth_status}: {unauth_payload}")

    mismatch_status, mismatch_payload = one_shot_request(
        root,
        token_file,
        select_path,
        context_body(session_id="different-session"),
        token=TOKEN,
    )
    if mismatch_status != 400:
        raise RuntimeError(
            f"expected 400 for path/body session mismatch, got {mismatch_status}: {mismatch_payload}"
        )

    scope_status, scope_payload = one_shot_request(
        root,
        token_file,
        select_path,
        context_body(scope="session:other"),
        token=TOKEN,
    )
    if scope_status != 403:
        raise RuntimeError(
            f"expected 403 for memory scope mismatch, got {scope_status}: {scope_payload}"
        )

    selected_status, selected_payload = one_shot_request(
        root, token_file, select_path, context_body(), token=TOKEN
    )
    if selected_status != 200:
        raise RuntimeError(f"expected memory context 200, got {selected_status}: {selected_payload}")
    context = selected_payload.get("context", {})
    selected = context.get("selected", [])
    rejected = context.get("rejected", [])
    if [item.get("memory_id") for item in selected] != ["trusted-context"]:
        raise RuntimeError(f"expected only trusted context selected: {selected_payload}")
    rejection_reasons = {
        rejection.get("memory_id"): set(rejection.get("reasons", [])) for rejection in rejected
    }
    expected_rejections = {
        "secret-context": {"sensitivity_not_allowed", "source_data_class_denied"},
        "expired-context": {"expired"},
        "poisoned-context": {"source_taint_denied"},
        "policy-disallowed-context": {"access_policy_not_allowed"},
    }
    for memory_id, reasons in expected_rejections.items():
        if not reasons.issubset(rejection_reasons.get(memory_id, set())):
            raise RuntimeError(
                f"expected {memory_id} rejection reasons {sorted(reasons)}: {selected_payload}"
            )
    if selected_payload.get("selected_memories") != 1 or selected_payload.get("rejected_memories") != 4:
        raise RuntimeError(f"unexpected memory context counts: {selected_payload}")
    if not selected_payload.get("journal_root_hash") or selected_payload.get("journal_records", 0) < 6:
        raise RuntimeError(f"expected journal root evidence: {selected_payload}")
    if context.get("selection_policy", {}).get("scope") != MEMORY_SCOPE:
        raise RuntimeError(f"expected session memory_scope default in selection policy: {selected_payload}")

    report = {
        "command": "beater-osd-http-memory-context-smoke",
        "session_id": SESSION_ID,
        "selected": selected[0]["memory_id"],
        "rejected": sorted(rejection_reasons),
        "journal_records": selected_payload["journal_records"],
        "journal_root_hash": selected_payload["journal_root_hash"],
    }
    if as_json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print("beater-osd-http memory-context smoke OK")
        print(f"  session: {report['session_id']}")
        print(f"  selected: {report['selected']}")
        print(f"  rejected: {report['rejected']}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit machine-readable smoke output")
    parser.add_argument("--keep-root", action="store_true", help="preserve the temporary store root")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="beater-osd-http-memory-context-smoke-") as temporary:
        root = Path(temporary)
        try:
            code = run_smoke(root, as_json=args.json)
            if args.keep_root:
                stable = Path(tempfile.mkdtemp(prefix="beater-osd-http-memory-context-smoke-keep-"))
                shutil.copytree(root, stable, dirs_exist_ok=True)
                print(f"beater-osd-http memory-context smoke root preserved at: {stable}")
            return code
        except Exception as error:
            if args.keep_root:
                stable = Path(
                    tempfile.mkdtemp(prefix="beater-osd-http-memory-context-smoke-failed-")
                )
                shutil.copytree(root, stable, dirs_exist_ok=True)
                print(f"beater-osd-http memory-context smoke root preserved at: {stable}")
            print(f"beater-osd-http memory-context smoke failed: {error}", file=sys.stderr)
            return 1


if __name__ == "__main__":
    sys.exit(main())
