"""Tests for the signed-webhook replay helper used to dogfood without a tunnel."""

from __future__ import annotations

import json
from typing import Any

import httpx

from heimdall.webhook import _build_job, compute_signature, verify_signature
from scripts.replay_webhook import build_pull_request_payload, post_replay

_SECRET = "replay-secret"


def _payload(
    *,
    action: str = "opened",
    pr_number: int = 7,
    head_sha: str = "deadbeef",
    repo_full_name: str = "owner/repo",
    installation_id: int = 99,
    draft: bool = False,
) -> dict[str, Any]:
    return build_pull_request_payload(
        action=action,
        pr_number=pr_number,
        head_sha=head_sha,
        repo_full_name=repo_full_name,
        installation_id=installation_id,
        draft=draft,
    )


def test_payload_shape_is_accepted_by_build_job() -> None:
    """The replayed payload carries every field the real webhook consumer reads."""
    job = _build_job(_payload())
    assert job.installation_id == 99
    assert job.repo_full_name == "owner/repo"
    assert job.pr_number == 7
    assert job.head_sha == "deadbeef"


def test_payload_defaults_to_non_draft() -> None:
    """draft defaults to False so the PR is not silently skipped by the draft filter."""
    assert _payload()["pull_request"]["draft"] is False
    assert _payload(draft=True)["pull_request"]["draft"] is True


def test_post_replay_signs_and_sets_github_headers() -> None:
    """post_replay POSTs JSON with the pull_request event and a matching HMAC header."""
    captured: dict[str, httpx.Request] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["request"] = request
        return httpx.Response(202)

    payload = _payload()
    client = httpx.Client(transport=httpx.MockTransport(handler))
    response = post_replay(
        url="http://test.local/webhook", secret=_SECRET, payload=payload, client=client
    )

    assert response.status_code == 202
    request = captured["request"]
    assert request.headers["X-GitHub-Event"] == "pull_request"
    # The signature must verify against the exact bytes that were sent.
    assert request.headers["X-Hub-Signature-256"] == compute_signature(
        request.content, _SECRET
    )
    verify_signature(request.content, _SECRET, request.headers["X-Hub-Signature-256"])
    assert json.loads(request.content) == payload
