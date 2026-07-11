#!/usr/bin/env python3
"""Exercise beater-osd-http's token-gated model-route selection boundary."""

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
TOKEN = "beateros-http-model-router-smoke-token"
SESSION_ID = "http-model-router-smoke-session"
RELEASE_EVAL_FIXTURES = [
    "k11_model_route_internal_allowed_journaled",
    "k11_model_route_secret_data_denied_no_selected_route",
]


def free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def start_server(
    root: Path, token_file: Path, catalog_file: Path, port: int
) -> subprocess.Popen[str]:
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
            "--model-route-catalog",
            str(catalog_file),
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
    catalog_file: Path,
    path: str,
    body: dict[str, Any],
    *,
    token: str | None,
) -> tuple[int, dict[str, Any]]:
    port = free_loopback_port()
    server = start_server(root, token_file, catalog_file, port)
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
            "agent_id": "agent:http-model-router-smoke",
            "workspace_id": "workspace:http-model-router-smoke",
            "goal": "choose a policy-compliant model route",
            "model_policy": {
                "allowed_routes": ["cloud/planner", "local/verifier"],
                "local_only": False,
                "max_data_class": "internal",
            },
        },
        "grants": [],
        "steps": [],
    }


def trusted_route_catalog() -> list[dict[str, Any]]:
    return [
        {
            "route_id": "local/verifier",
            "provider": "local",
            "model": "verifier-small",
            "model_version": "2026-07",
            "locality": "local",
            "retention": "none",
            "max_data_class": None,
            "allowed_purposes": ["verifier"],
            "pricing": {
                "input_cents_per_million_tokens": 0,
                "output_cents_per_million_tokens": 0,
            },
            "p95_latency_ms": 40,
            "max_context_tokens": 32000,
            "max_output_tokens": 4096,
            "supports_tools": False,
            "supports_multimodal": False,
            "enabled": True,
        },
        {
            "route_id": "cloud/planner",
            "provider": "frontier-cloud",
            "model": "planner-large",
            "model_version": "2026-07",
            "locality": "public_cloud",
            "retention": "no_training",
            "max_data_class": "internal",
            "allowed_purposes": ["planner"],
            "pricing": {
                "input_cents_per_million_tokens": 300,
                "output_cents_per_million_tokens": 1500,
            },
            "p95_latency_ms": 900,
            "max_context_tokens": 200000,
            "max_output_tokens": 16384,
            "supports_tools": True,
            "supports_multimodal": True,
            "enabled": True,
        },
    ]


def planner_route_body(session_id: str = SESSION_ID, data_class: str = "internal") -> dict[str, Any]:
    return {
        "session_id": session_id,
        "request": {
            "session_id": session_id,
            "purpose": "planner",
            "data_classes": [data_class],
            "taint": [],
            "estimated_input_tokens": 2000,
            "max_output_tokens": 1000,
            "max_estimated_cents": 10,
            "required_tools": True,
            "max_retention": "no_training",
        },
    }


def rejected_reasons(decision: dict[str, Any], route_id: str) -> set[str]:
    for rejection in decision.get("rejected_routes", []):
        if rejection.get("route_id") == route_id:
            return set(rejection.get("reasons", []))
    return set()


def run_smoke(root: Path, *, as_json: bool) -> int:
    token_file = root / "token"
    token_file.write_text(TOKEN, encoding="utf-8")
    catalog_file = root / "model-routes.json"
    catalog_file.write_text(json.dumps(trusted_route_catalog(), indent=2), encoding="utf-8")

    status, payload = one_shot_request(
        root,
        token_file,
        catalog_file,
        "/v1/runtime/bundles",
        bootstrap_body(),
        token=TOKEN,
    )
    if status != 200:
        raise RuntimeError(f"expected session bootstrap 200, got {status}: {payload}")
    if payload.get("session_id") != SESSION_ID or not payload.get("created_session"):
        raise RuntimeError(f"unexpected bootstrap response: {payload}")

    path = f"/v1/sessions/{SESSION_ID}/model-routes/choose"
    unauth_status, unauth_payload = one_shot_request(
        root, token_file, catalog_file, path, planner_route_body(), token=None
    )
    if unauth_status != 401:
        raise RuntimeError(f"expected 401 without token, got {unauth_status}: {unauth_payload}")

    mismatch_status, mismatch_payload = one_shot_request(
        root,
        token_file,
        catalog_file,
        path,
        planner_route_body(session_id="different-session"),
        token=TOKEN,
    )
    if mismatch_status != 400:
        raise RuntimeError(
            f"expected 400 for path/body session mismatch, got {mismatch_status}: {mismatch_payload}"
        )

    allowed_status, allowed_payload = one_shot_request(
        root, token_file, catalog_file, path, planner_route_body(), token=TOKEN
    )
    if allowed_status != 200:
        raise RuntimeError(f"expected model route 200, got {allowed_status}: {allowed_payload}")
    decision = allowed_payload.get("decision", {})
    selected = decision.get("selected") or {}
    if decision.get("result") != "allowed" or selected.get("route_id") != "cloud/planner":
        raise RuntimeError(f"expected cloud planner route selection: {allowed_payload}")
    if decision.get("policy_summary", {}).get("max_data_class") != "internal":
        raise RuntimeError(f"expected daemon-projected internal data ceiling: {allowed_payload}")
    if not isinstance(allowed_payload.get("journal_seq"), int) or not allowed_payload.get(
        "journal_record_hash"
    ):
        raise RuntimeError(f"expected journaled route-decision evidence: {allowed_payload}")
    if allowed_payload.get("projection", {}).get("model_route_decisions") != 1:
        raise RuntimeError(f"expected one projected route decision: {allowed_payload}")

    denied_status, denied_payload = one_shot_request(
        root, token_file, catalog_file, path, planner_route_body(data_class="secret"), token=TOKEN
    )
    if denied_status != 200:
        raise RuntimeError(f"expected denied route decision 200, got {denied_status}: {denied_payload}")
    denied_decision = denied_payload.get("decision", {})
    if denied_decision.get("result") != "denied" or denied_decision.get("selected") is not None:
        raise RuntimeError(f"expected denied decision for secret data: {denied_payload}")
    if "data_class_too_high" not in rejected_reasons(denied_decision, "cloud/planner"):
        raise RuntimeError(f"expected data_class_too_high rejection: {denied_payload}")
    if not isinstance(denied_payload.get("journal_seq"), int) or not denied_payload.get(
        "journal_record_hash"
    ):
        raise RuntimeError(f"expected journaled denied-route evidence: {denied_payload}")
    if denied_payload.get("projection", {}).get("model_route_decisions") != 2:
        raise RuntimeError(f"expected two projected route decisions: {denied_payload}")

    report = {
        "command": "beater-osd-http-model-router-smoke",
        "session_id": SESSION_ID,
        "selected_route": selected["route_id"],
        "allowed_decision_id": decision["decision_id"],
        "allowed_journal_hash": allowed_payload["journal_record_hash"],
        "denied_result": denied_decision["result"],
        "denied_journal_hash": denied_payload["journal_record_hash"],
        "projection_model_route_decisions": denied_payload.get("projection", {}).get(
            "model_route_decisions"
        ),
        "release_eval_fixtures": RELEASE_EVAL_FIXTURES,
    }
    if as_json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print("beater-osd-http model-router smoke OK")
        print(f"  session: {report['session_id']}")
        print(f"  selected: {report['selected_route']}")
        print(f"  denied: {report['denied_result']}")
        print(f"  release eval fixtures: {', '.join(RELEASE_EVAL_FIXTURES)}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit machine-readable smoke output")
    parser.add_argument("--keep-root", action="store_true", help="preserve the temporary store root")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="beater-osd-http-model-router-smoke-") as temporary:
        root = Path(temporary)
        try:
            code = run_smoke(root, as_json=args.json)
            if args.keep_root:
                stable = Path(tempfile.mkdtemp(prefix="beater-osd-http-model-router-smoke-keep-"))
                shutil.copytree(root, stable, dirs_exist_ok=True)
                print(f"beater-osd-http model-router smoke root preserved at: {stable}")
            return code
        except Exception as error:
            if args.keep_root:
                stable = Path(tempfile.mkdtemp(prefix="beater-osd-http-model-router-smoke-failed-"))
                shutil.copytree(root, stable, dirs_exist_ok=True)
                print(f"beater-osd-http model-router smoke root preserved at: {stable}")
            print(f"beater-osd-http model-router smoke failed: {error}", file=sys.stderr)
            return 1


if __name__ == "__main__":
    sys.exit(main())
