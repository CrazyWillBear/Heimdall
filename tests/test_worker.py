"""Tests for the Arq worker: runs the security lens and posts one review."""

from __future__ import annotations

from contextlib import ExitStack
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from heimdall.lens import (
    Finding,
    LensError,
    LensResult,
    LensTimeoutError,
    Severity,
)
from heimdall.worker import WorkerSettings, run_review

_REPO = "owner/repo"
_PR = 3
_SHA = "sha1234"
_INSTALL_ID = 42
_APP_ID = 1
_PRIVATE_KEY = "key"


def _lens_result(findings: list[Finding]) -> LensResult:
    return LensResult(lens_name="security", findings=findings)


def _patch_review_pipeline(
    *,
    lens_result: LensResult | None = None,
    lens_side_effect: BaseException | None = None,
    last_sha: str | None = None,
) -> ExitStack:
    """Patch the worker's seed-assembly, lens run, and SHA helpers in one block.

    Returns an ExitStack-managed context manager; callers use it under ``with``.
    """
    stack = ExitStack()
    stack.enter_context(
        patch("heimdall.worker.get_last_reviewed_sha", new=AsyncMock(return_value=last_sha))
    )
    stack.enter_context(
        patch("heimdall.worker.assemble_pr_context", new=AsyncMock(return_value=MagicMock()))
    )
    if lens_side_effect is not None:
        run_lens_mock: AsyncMock = AsyncMock(side_effect=lens_side_effect)
    else:
        run_lens_mock = AsyncMock(return_value=lens_result)
    stack.enter_context(patch("heimdall.worker.run_lens", new=run_lens_mock))
    return stack


# ---------------------------------------------------------------------------
# run_review: ctx contract — builds GitHubClient per job from app credentials
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_review_posts_exactly_one_review() -> None:
    """Worker builds a per-job GitHubClient and posts exactly one review."""
    mock_db = AsyncMock()
    mock_gh_client = AsyncMock()
    mock_gh_client.post_review = AsyncMock()

    ctx: dict[str, object] = {
        "db": mock_db,
        "app_id": _APP_ID,
        "private_key": _PRIVATE_KEY,
    }

    findings = [Finding(severity=Severity.LOW, title="nit", message="style", location=None)]
    with (
        _patch_review_pipeline(lens_result=_lens_result(findings)),
        patch("heimdall.worker.set_last_reviewed_sha", new=AsyncMock()) as mock_set,
        patch("heimdall.worker.GitHubClient", return_value=mock_gh_client) as mock_cls,
    ):
        await run_review(
            ctx,
            installation_id=_INSTALL_ID,
            repo_full_name=_REPO,
            pr_number=_PR,
            head_sha=_SHA,
        )

    mock_cls.assert_called_once_with(
        app_id=_APP_ID,
        private_key=_PRIVATE_KEY,
        installation_id=_INSTALL_ID,
    )
    mock_gh_client.post_review.assert_awaited_once()
    assert mock_gh_client.post_review.await_count == 1
    mock_set.assert_awaited_once_with(
        mock_db, repo_full_name=_REPO, pr_number=_PR, sha=_SHA
    )


@pytest.mark.asyncio
async def test_run_review_reflects_planted_finding_in_body() -> None:
    """A planted security finding (mocked lens output) shows up in the review body."""
    mock_gh_client = AsyncMock()
    ctx: dict[str, object] = {"db": AsyncMock(), "app_id": _APP_ID, "private_key": _PRIVATE_KEY}

    findings = [
        Finding(
            severity=Severity.HIGH,
            title="SQL injection",
            message="User input concatenated into a query",
            location="app/db.py:12",
        )
    ]
    with (
        _patch_review_pipeline(lens_result=_lens_result(findings)),
        patch("heimdall.worker.set_last_reviewed_sha", new=AsyncMock()),
        patch("heimdall.worker.GitHubClient", return_value=mock_gh_client),
    ):
        await run_review(
            ctx,
            installation_id=_INSTALL_ID,
            repo_full_name=_REPO,
            pr_number=_PR,
            head_sha=_SHA,
        )

    posted = mock_gh_client.post_review.await_args.kwargs
    assert "SQL injection" in posted["body"]
    assert "app/db.py:12" in posted["body"]


@pytest.mark.asyncio
async def test_run_review_high_finding_requests_changes() -> None:
    """A high/critical finding posts event=REQUEST_CHANGES."""
    mock_gh_client = AsyncMock()
    ctx: dict[str, object] = {"db": AsyncMock(), "app_id": _APP_ID, "private_key": _PRIVATE_KEY}

    findings = [Finding(severity=Severity.HIGH, title="x", message="m", location=None)]
    with (
        _patch_review_pipeline(lens_result=_lens_result(findings)),
        patch("heimdall.worker.set_last_reviewed_sha", new=AsyncMock()),
        patch("heimdall.worker.GitHubClient", return_value=mock_gh_client),
    ):
        await run_review(
            ctx,
            installation_id=_INSTALL_ID,
            repo_full_name=_REPO,
            pr_number=_PR,
            head_sha=_SHA,
        )

    assert mock_gh_client.post_review.await_args.kwargs["event"] == "REQUEST_CHANGES"


@pytest.mark.asyncio
async def test_run_review_no_findings_posts_comment() -> None:
    """No findings posts event=COMMENT."""
    mock_gh_client = AsyncMock()
    ctx: dict[str, object] = {"db": AsyncMock(), "app_id": _APP_ID, "private_key": _PRIVATE_KEY}

    with (
        _patch_review_pipeline(lens_result=_lens_result([])),
        patch("heimdall.worker.set_last_reviewed_sha", new=AsyncMock()),
        patch("heimdall.worker.GitHubClient", return_value=mock_gh_client),
    ):
        await run_review(
            ctx,
            installation_id=_INSTALL_ID,
            repo_full_name=_REPO,
            pr_number=_PR,
            head_sha=_SHA,
        )

    assert mock_gh_client.post_review.await_args.kwargs["event"] == "COMMENT"


@pytest.mark.asyncio
async def test_run_review_handles_lens_failure_without_crashing() -> None:
    """A persistent lens timeout is handled gracefully: no crash, posts a terse note."""
    mock_gh_client = AsyncMock()
    ctx: dict[str, object] = {"db": AsyncMock(), "app_id": _APP_ID, "private_key": _PRIVATE_KEY}

    with (
        _patch_review_pipeline(lens_side_effect=LensTimeoutError("killed")),
        patch("heimdall.worker.set_last_reviewed_sha", new=AsyncMock()),
        patch("heimdall.worker.GitHubClient", return_value=mock_gh_client),
    ):
        # Must not raise — the worker swallows lens failures gracefully.
        await run_review(
            ctx,
            installation_id=_INSTALL_ID,
            repo_full_name=_REPO,
            pr_number=_PR,
            head_sha=_SHA,
        )

    # After retry-once also fails, a single terse COMMENT note is posted.
    mock_gh_client.post_review.assert_awaited_once()
    assert mock_gh_client.post_review.await_args.kwargs["event"] == "COMMENT"
    mock_gh_client.aclose.assert_awaited_once()


# ---------------------------------------------------------------------------
# Retry-once + per-review timeout + terse failure note
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_review_retries_lens_exactly_once_then_posts_terse_note() -> None:
    """A failing review is retried exactly once, then posts a terse error COMMENT."""
    mock_gh_client = AsyncMock()
    ctx: dict[str, object] = {"db": AsyncMock(), "app_id": _APP_ID, "private_key": _PRIVATE_KEY}

    run_lens_mock = AsyncMock(side_effect=LensError("boom"))
    with (
        patch("heimdall.worker.get_last_reviewed_sha", new=AsyncMock(return_value=None)),
        patch("heimdall.worker.assemble_pr_context", new=AsyncMock(return_value=MagicMock())),
        patch("heimdall.worker.run_lens", new=run_lens_mock),
        patch("heimdall.worker.set_last_reviewed_sha", new=AsyncMock()) as mock_set,
        patch("heimdall.worker.GitHubClient", return_value=mock_gh_client),
    ):
        await run_review(
            ctx,
            installation_id=_INSTALL_ID,
            repo_full_name=_REPO,
            pr_number=_PR,
            head_sha=_SHA,
        )

    # Exactly two attempts: the initial run plus a single retry.
    assert run_lens_mock.await_count == 2
    # Terse failure note posted exactly once as a COMMENT, never REQUEST_CHANGES.
    mock_gh_client.post_review.assert_awaited_once()
    posted = mock_gh_client.post_review.await_args.kwargs
    assert posted["event"] == "COMMENT"
    assert "failed" in posted["body"].lower()
    # The failed SHA is recorded so it is not endlessly re-reviewed.
    mock_set.assert_awaited_once()


@pytest.mark.asyncio
async def test_run_review_retry_succeeds_posts_real_review() -> None:
    """If the retry succeeds, the real review is posted (no failure note)."""
    mock_gh_client = AsyncMock()
    ctx: dict[str, object] = {"db": AsyncMock(), "app_id": _APP_ID, "private_key": _PRIVATE_KEY}

    findings = [Finding(severity=Severity.LOW, title="nit", message="style", location=None)]
    # First attempt raises, second attempt returns a clean lens result.
    run_lens_mock = AsyncMock(side_effect=[LensError("boom"), _lens_result(findings)])
    with (
        patch("heimdall.worker.get_last_reviewed_sha", new=AsyncMock(return_value=None)),
        patch("heimdall.worker.assemble_pr_context", new=AsyncMock(return_value=MagicMock())),
        patch("heimdall.worker.run_lens", new=run_lens_mock),
        patch("heimdall.worker.set_last_reviewed_sha", new=AsyncMock()),
        patch("heimdall.worker.GitHubClient", return_value=mock_gh_client),
    ):
        await run_review(
            ctx,
            installation_id=_INSTALL_ID,
            repo_full_name=_REPO,
            pr_number=_PR,
            head_sha=_SHA,
        )

    assert run_lens_mock.await_count == 2
    mock_gh_client.post_review.assert_awaited_once()
    posted = mock_gh_client.post_review.await_args.kwargs
    # A real verdict, not the terse failure note.
    assert "failed" not in posted["body"].lower()


@pytest.mark.asyncio
async def test_run_review_pipeline_timeout_surfaced_as_failure() -> None:
    """A run exceeding the per-review wall-clock timeout posts a terse failure note."""
    mock_gh_client = AsyncMock()
    # Tiny per-review timeout; the lens sleeps past it on every attempt.
    ctx: dict[str, object] = {
        "db": AsyncMock(),
        "app_id": _APP_ID,
        "private_key": _PRIVATE_KEY,
        "review_timeout_seconds": 0.01,
    }

    async def _slow_lens(*_args: object, **_kwargs: object) -> object:
        import asyncio

        await asyncio.sleep(1.0)
        return _lens_result([])

    run_lens_mock = AsyncMock(side_effect=_slow_lens)
    with (
        patch("heimdall.worker.get_last_reviewed_sha", new=AsyncMock(return_value=None)),
        patch("heimdall.worker.assemble_pr_context", new=AsyncMock(return_value=MagicMock())),
        patch("heimdall.worker.run_lens", new=run_lens_mock),
        patch("heimdall.worker.set_last_reviewed_sha", new=AsyncMock()),
        patch("heimdall.worker.GitHubClient", return_value=mock_gh_client),
    ):
        await run_review(
            ctx,
            installation_id=_INSTALL_ID,
            repo_full_name=_REPO,
            pr_number=_PR,
            head_sha=_SHA,
        )

    # The timeout is surfaced as a failure: terse COMMENT note after retry.
    mock_gh_client.post_review.assert_awaited_once()
    posted = mock_gh_client.post_review.await_args.kwargs
    assert posted["event"] == "COMMENT"
    assert "failed" in posted["body"].lower()


@pytest.mark.asyncio
async def test_run_review_skips_already_reviewed_sha() -> None:
    """Worker skips posting (and the lens) if the head SHA was already reviewed."""
    mock_gh_client = AsyncMock()
    ctx: dict[str, object] = {"db": AsyncMock(), "app_id": _APP_ID, "private_key": _PRIVATE_KEY}

    with (
        _patch_review_pipeline(lens_result=_lens_result([]), last_sha=_SHA),
        patch("heimdall.worker.GitHubClient", return_value=mock_gh_client),
    ):
        await run_review(
            ctx,
            installation_id=_INSTALL_ID,
            repo_full_name=_REPO,
            pr_number=_PR,
            head_sha=_SHA,
        )

    mock_gh_client.post_review.assert_not_called()


@pytest.mark.asyncio
async def test_run_review_closes_github_client_after_posting() -> None:
    """run_review closes the GitHubClient after posting a review (no FD leak)."""
    mock_gh_client = AsyncMock()
    mock_gh_client.post_review = AsyncMock()
    ctx: dict[str, object] = {"db": AsyncMock(), "app_id": _APP_ID, "private_key": _PRIVATE_KEY}

    with (
        _patch_review_pipeline(lens_result=_lens_result([])),
        patch("heimdall.worker.set_last_reviewed_sha", new=AsyncMock()),
        patch("heimdall.worker.GitHubClient", return_value=mock_gh_client),
    ):
        await run_review(
            ctx,
            installation_id=_INSTALL_ID,
            repo_full_name=_REPO,
            pr_number=_PR,
            head_sha=_SHA,
        )

    mock_gh_client.aclose.assert_awaited_once()


@pytest.mark.asyncio
async def test_run_review_closes_github_client_on_skip_path() -> None:
    """run_review closes the GitHubClient even when the review is skipped."""
    mock_gh_client = AsyncMock()
    ctx: dict[str, object] = {"db": AsyncMock(), "app_id": _APP_ID, "private_key": _PRIVATE_KEY}

    with (
        _patch_review_pipeline(lens_result=_lens_result([]), last_sha=_SHA),
        patch("heimdall.worker.GitHubClient", return_value=mock_gh_client),
    ):
        await run_review(
            ctx,
            installation_id=_INSTALL_ID,
            repo_full_name=_REPO,
            pr_number=_PR,
            head_sha=_SHA,
        )

    mock_gh_client.aclose.assert_awaited_once()


# ---------------------------------------------------------------------------
# Metadata-only logging: no token/secret/findings by default; findings under DEBUG
# ---------------------------------------------------------------------------

_TOKEN = "ghs_supersecretinstallationtoken"
_SECRET_KEY = "-----BEGIN RSA PRIVATE KEY-----\nMIIsecret\n-----END RSA PRIVATE KEY-----"
_API_KEY = "sk-ant-supersecretanthropickey"
_FINDING_TITLE = "SQL injection via unsanitized id"
_FINDING_MESSAGE = "User input concatenated into a raw query string"


async def _drive_review_capturing_logs(
    *,
    debug_logging: bool,
) -> str:
    """Run a successful review under the given debug flag; return the full log text."""
    import logging

    mock_gh_client = AsyncMock()
    ctx: dict[str, object] = {
        "db": AsyncMock(),
        # Secrets the worker handles but must never log.
        "app_id": _APP_ID,
        "private_key": _SECRET_KEY,
        "installation_token": _TOKEN,
        "anthropic_api_key": _API_KEY,
        "debug_logging": debug_logging,
    }
    findings = [
        Finding(
            severity=Severity.HIGH,
            title=_FINDING_TITLE,
            message=_FINDING_MESSAGE,
            location="app/db.py:12",
        )
    ]

    records: list[logging.LogRecord] = []

    class _Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    handler = _Capture()
    worker_logger = logging.getLogger("heimdall.worker")
    prev_level = worker_logger.level
    worker_logger.addHandler(handler)
    worker_logger.setLevel(logging.DEBUG)
    try:
        with (
            _patch_review_pipeline(lens_result=_lens_result(findings)),
            patch("heimdall.worker.set_last_reviewed_sha", new=AsyncMock()),
            patch("heimdall.worker.GitHubClient", return_value=mock_gh_client),
        ):
            await run_review(
                ctx,
                installation_id=_INSTALL_ID,
                repo_full_name=_REPO,
                pr_number=_PR,
                head_sha=_SHA,
            )
    finally:
        worker_logger.removeHandler(handler)
        worker_logger.setLevel(prev_level)

    return "\n".join(record.getMessage() for record in records)


@pytest.mark.asyncio
async def test_default_logs_contain_only_metadata_no_secrets_or_findings() -> None:
    """Default logs carry metadata only — no token, secret, or findings text."""
    log_text = await _drive_review_capturing_logs(debug_logging=False)

    # Metadata is present (repo, PR, SHA, verdict).
    assert _REPO in log_text
    assert _SHA in log_text

    # No secret material ever appears.
    assert _TOKEN not in log_text
    assert _SECRET_KEY not in log_text
    assert _API_KEY not in log_text
    assert "BEGIN RSA PRIVATE KEY" not in log_text

    # No findings/code text in default (metadata-only) logs.
    assert _FINDING_TITLE not in log_text
    assert _FINDING_MESSAGE not in log_text


@pytest.mark.asyncio
async def test_debug_logs_include_findings_and_code() -> None:
    """Under the DEBUG flag, findings/code text appears in the logs."""
    log_text = await _drive_review_capturing_logs(debug_logging=True)

    # Findings/code text appears only because DEBUG logging is enabled.
    assert _FINDING_TITLE in log_text
    assert _FINDING_MESSAGE in log_text

    # Even under DEBUG, secrets are never logged.
    assert _TOKEN not in log_text
    assert _SECRET_KEY not in log_text
    assert _API_KEY not in log_text


# ---------------------------------------------------------------------------
# WorkerSettings: registration and Redis wiring
# ---------------------------------------------------------------------------


def test_worker_settings_registers_run_review() -> None:
    """WorkerSettings.functions must include run_review."""
    assert run_review in WorkerSettings.functions


def test_worker_settings_has_redis_settings() -> None:
    """WorkerSettings.redis_settings must be an ArqRedisSettings instance."""
    from arq.connections import RedisSettings

    assert isinstance(WorkerSettings.redis_settings, RedisSettings)


# ---------------------------------------------------------------------------
# WorkerSettings.on_startup / on_shutdown lifecycle
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_on_startup_populates_ctx() -> None:
    """on_startup stores db, app_id, and private_key in ctx."""
    ctx: dict[str, object] = {}
    mock_db = AsyncMock()

    with (
        patch("heimdall.worker.Database", return_value=mock_db),
        patch("heimdall.worker.settings") as mock_settings,
    ):
        mock_settings.database_url = "sqlite+aiosqlite:///./test.db"
        mock_settings.redis_url = "redis://localhost:6379"
        mock_settings.github_app_id = _APP_ID
        mock_settings.github_app_private_key = _PRIVATE_KEY

        await WorkerSettings.on_startup(ctx)

    mock_db.initialize.assert_awaited_once()
    assert ctx["db"] is mock_db
    assert ctx["app_id"] == _APP_ID
    assert ctx["private_key"] == _PRIVATE_KEY


@pytest.mark.asyncio
async def test_on_shutdown_closes_db() -> None:
    """on_shutdown closes the Database stored in ctx."""
    mock_db = AsyncMock()
    ctx: dict[str, object] = {"db": mock_db}

    await WorkerSettings.on_shutdown(ctx)

    mock_db.close.assert_awaited_once()


@pytest.mark.asyncio
async def test_on_startup_strips_sqlalchemy_prefix() -> None:
    """on_startup converts SQLAlchemy DSN to plain aiosqlite path for Database."""
    ctx: dict[str, object] = {}
    mock_db = MagicMock()
    mock_db.initialize = AsyncMock()

    with (
        patch("heimdall.worker.Database", return_value=mock_db) as mock_cls,
        patch("heimdall.worker.settings") as mock_settings,
    ):
        mock_settings.database_url = "sqlite+aiosqlite:///./heimdall.db"
        mock_settings.redis_url = "redis://localhost:6379"
        mock_settings.github_app_id = _APP_ID
        mock_settings.github_app_private_key = _PRIVATE_KEY

        await WorkerSettings.on_startup(ctx)

    # Database must receive a plain filesystem path, not a SQLAlchemy DSN
    call_args = mock_cls.call_args
    db_path: str = call_args[0][0] if call_args[0] else call_args[1].get("path", "")
    assert not db_path.startswith("sqlite+aiosqlite"), (
        f"Database received raw SQLAlchemy DSN: {db_path!r}"
    )
