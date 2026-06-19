"""Arq worker: the run_review task function and WorkerSettings.

Context keys populated by WorkerSettings.on_startup:
    db:                     heimdall.db.Database instance
    app_id:                 GitHub App numeric ID (int)
    private_key:            PEM-encoded RSA private key (str)
    claude_binary:          path/name of the claude CLI (str)
    lens_token_cap:         per-agent cumulative-token cap (int)
    lens_timeout_seconds:   per-lens wall-clock timeout (float)
    review_timeout_seconds: per-review wall-clock timeout across the pipeline (float)
    debug_logging:          when True, log findings/code text (else metadata-only) (bool)

run_review builds a GitHubClient per-job using ctx["app_id"], ctx["private_key"],
and the per-job installation_id argument.  It assembles the PR seed context into
a temporary workspace, runs the Security lens (``claude -p``) over it, maps the
findings to a verdict, and posts exactly one PR review.

The whole review pipeline is wrapped in a per-review wall-clock timeout (distinct
from the per-lens timeout) and retried exactly once on any failure/timeout.  If the
retry also fails, a terse "review failed" COMMENT note is posted instead.  The job
never crashes the worker.

Logging is metadata-only by default — repo/PR/SHA/timing/verdict — and never logs
tokens or secrets.  Findings and code text are logged only when ``debug_logging`` is
set in ctx.

Launch the worker with:
    arq heimdall.worker.WorkerSettings
"""

from __future__ import annotations

import asyncio
import logging
import shutil
import tempfile
from typing import Any

from arq.connections import RedisSettings

from heimdall.context import assemble_pr_context
from heimdall.db import Database, get_last_reviewed_sha, set_last_reviewed_sha
from heimdall.github import GitHubClient
from heimdall.lens import (
    DEFAULT_TIMEOUT_SECONDS,
    DEFAULT_TOKEN_CAP,
    SECURITY_LENS,
    LensError,
    format_review_body,
    run_lens,
    verdict_for,
)

logger = logging.getLogger(__name__)

# Per-review wall-clock timeout across the whole pipeline (assembly + lens(es) +
# verdict mapping), distinct from and looser than the per-lens timeout: it bounds
# the total job even if the inner pipeline grows more stages (#5).
DEFAULT_REVIEW_TIMEOUT_SECONDS = 2_400.0

# Posted as a COMMENT (never REQUEST_CHANGES) when both the initial run and the
# single retry fail — a deliberately terse, metadata-free note.
_REVIEW_FAILED_NOTE = (
    "Heimdall review failed: the automated review could not complete after a retry. "
    "No verdict was produced for this commit."
)


def _db_path_from_url(database_url: str) -> str:
    """Strip the SQLAlchemy driver prefix from a database URL for aiosqlite.

    aiosqlite.connect expects a plain file path (or ':memory:'), not a full
    SQLAlchemy DSN.  We only support the sqlite+aiosqlite:/// scheme used by
    the default config.
    """
    prefix = "sqlite+aiosqlite:///"
    if database_url.startswith(prefix):
        return database_url[len(prefix):]
    # Fallback: pass through as-is so plain paths still work in tests
    return database_url


async def run_review(
    ctx: dict[str, Any],
    *,
    installation_id: int,
    repo_full_name: str,
    pr_number: int,
    head_sha: str,
) -> None:
    """Arq task: run the review pipeline over the PR and post one review.

    Skips if the same head SHA was already reviewed (idempotency guard).  On a
    fresh SHA it runs the review pipeline — assemble seed context, run the
    lens(es), map findings to a verdict (REQUEST_CHANGES for any high/critical
    finding, else COMMENT) — under a per-review wall-clock timeout, retrying the
    whole pipeline exactly once on any failure/timeout.  On success it posts
    exactly one PR review and records the SHA.  If the retry also fails, a terse
    "review failed" COMMENT note is posted and the SHA is recorded so the failed
    commit is not endlessly re-reviewed.

    A GitHubClient is constructed per-job from the app credentials in ctx so
    that each job can target a different GitHub App installation.

    Args:
        ctx: Arq worker context carrying ``db``, ``app_id``, ``private_key``,
            and the optional lens/review/logging knobs.
        installation_id: GitHub App installation ID for this PR.
        repo_full_name: e.g. "owner/repo".
        pr_number: The pull-request number.
        head_sha: The commit SHA to review.
    """
    db = ctx["db"]
    github_client = GitHubClient(
        app_id=ctx["app_id"],
        private_key=ctx["private_key"],
        installation_id=installation_id,
    )
    try:
        last_sha = await get_last_reviewed_sha(
            db, repo_full_name=repo_full_name, pr_number=pr_number
        )
        if last_sha == head_sha:
            logger.info(
                "Skipping already-reviewed SHA %s for %s#%d",
                head_sha,
                repo_full_name,
                pr_number,
            )
            return

        review = await _run_pipeline_with_retry(
            ctx,
            installation_id=installation_id,
            repo_full_name=repo_full_name,
            pr_number=pr_number,
            head_sha=head_sha,
        )
        if review is None:
            await _post_review_failed_note(
                github_client,
                repo_full_name=repo_full_name,
                pr_number=pr_number,
                head_sha=head_sha,
            )
            await set_last_reviewed_sha(
                db, repo_full_name=repo_full_name, pr_number=pr_number, sha=head_sha
            )
            return

        body, event = review
        logger.info(
            "Posting %s review for %s#%d @ %s",
            event,
            repo_full_name,
            pr_number,
            head_sha,
        )
        await github_client.post_review(
            repo_full_name=repo_full_name,
            pr_number=pr_number,
            commit_id=head_sha,
            body=body,
            event=event,
        )
        await set_last_reviewed_sha(
            db, repo_full_name=repo_full_name, pr_number=pr_number, sha=head_sha
        )
        logger.info(
            "Review posted for %s#%d @ %s", repo_full_name, pr_number, head_sha
        )
    finally:
        await github_client.aclose()


async def _run_pipeline_with_retry(
    ctx: dict[str, Any],
    *,
    installation_id: int,
    repo_full_name: str,
    pr_number: int,
    head_sha: str,
) -> tuple[str, str] | None:
    """Run the review pipeline under a per-review timeout, retrying once on failure.

    Wraps :func:`_run_review_pipeline` in :func:`asyncio.wait_for` to enforce the
    per-review wall-clock budget (separate from the per-lens timeout), then retries
    the whole wrapped pipeline exactly once on any failure/timeout.  The retry seam
    is deliberately outside the pipeline body so #5's lens-fanout restructure slots
    inside :func:`_run_review_pipeline` without touching this wrapper.

    Returns:
        A ``(review_body, review_event)`` tuple on success, or None when both the
        initial run and the single retry fail (lens abort or per-review timeout).
    """
    review_timeout = ctx.get(
        "review_timeout_seconds", DEFAULT_REVIEW_TIMEOUT_SECONDS
    )
    max_attempts = 2  # one initial attempt + exactly one retry
    for attempt in range(1, max_attempts + 1):
        try:
            return await asyncio.wait_for(
                _run_review_pipeline(
                    ctx,
                    installation_id=installation_id,
                    repo_full_name=repo_full_name,
                    pr_number=pr_number,
                ),
                timeout=review_timeout,
            )
        except (LensError, TimeoutError) as exc:
            # Metadata-only: log the failure class and identifiers, never the
            # underlying findings/code or any secret.
            logger.warning(
                "Review pipeline attempt %d/%d failed for %s#%d @ %s: %s",
                attempt,
                max_attempts,
                repo_full_name,
                pr_number,
                head_sha,
                type(exc).__name__,
            )
    logger.warning(
        "Review pipeline failed after retry for %s#%d @ %s; posting failure note",
        repo_full_name,
        pr_number,
        head_sha,
    )
    return None


async def _run_review_pipeline(
    ctx: dict[str, Any],
    *,
    installation_id: int,
    repo_full_name: str,
    pr_number: int,
) -> tuple[str, str]:
    """Assemble seed context, run the Security lens, and map to (body, event).

    The inner review pipeline core — wrapped by :func:`_run_pipeline_with_retry`
    for retry-once + per-review timeout.  The seed context is materialized into a
    temporary workspace that the lens reads via the heimdall-context wrapper; the
    workspace is removed afterwards.

    #5 expands this body into three lenses plus a synthesis pass; the surrounding
    retry/timeout wrapper is unaffected.

    Returns:
        A ``(review_body, review_event)`` tuple.

    Raises:
        LensError: Propagated when the lens aborts (timeout or token-cap breach);
            the wrapper catches it to drive the retry/failure-note path.
    """
    workspace = tempfile.mkdtemp(prefix="heimdall-lens-")
    try:
        await assemble_pr_context(
            app_id=ctx["app_id"],
            private_key=ctx["private_key"],
            installation_id=installation_id,
            repo_full_name=repo_full_name,
            pr_number=pr_number,
            workspace_dir=workspace,
        )
        result = await run_lens(
            lens=SECURITY_LENS,
            workspace_dir=workspace,
            claude_binary=ctx.get("claude_binary", "claude"),
            token_cap=ctx.get("lens_token_cap", DEFAULT_TOKEN_CAP),
            timeout_seconds=ctx.get("lens_timeout_seconds", DEFAULT_TIMEOUT_SECONDS),
        )
    finally:
        shutil.rmtree(workspace, ignore_errors=True)

    body = format_review_body(result.findings)
    event = verdict_for(result.findings)
    _log_findings(ctx, repo_full_name=repo_full_name, pr_number=pr_number, body=body)
    return body, event


def _log_findings(
    ctx: dict[str, Any],
    *,
    repo_full_name: str,
    pr_number: int,
    body: str,
) -> None:
    """Log the rendered review body only under the DEBUG-logging flag.

    The body carries findings and code-snippet text, so it is emitted only when
    ``ctx['debug_logging']`` is truthy.  Default (metadata-only) logging never
    sees it.
    """
    if ctx.get("debug_logging"):
        logger.debug(
            "Review body for %s#%d:\n%s", repo_full_name, pr_number, body
        )


async def _post_review_failed_note(
    github_client: GitHubClient,
    *,
    repo_full_name: str,
    pr_number: int,
    head_sha: str,
) -> None:
    """Post the terse "review failed" COMMENT note after the retry also failed.

    Deliberately a COMMENT (never REQUEST_CHANGES): a pipeline failure is not a
    verdict on the code, so it must not block the PR.
    """
    logger.info(
        "Posting review-failed note for %s#%d @ %s",
        repo_full_name,
        pr_number,
        head_sha,
    )
    await github_client.post_review(
        repo_full_name=repo_full_name,
        pr_number=pr_number,
        commit_id=head_sha,
        body=_REVIEW_FAILED_NOTE,
        event="COMMENT",
    )


def _load_settings() -> Any:
    """Load Settings lazily, allowing tests to patch before first access."""
    from heimdall.config import Settings

    return Settings()  # type: ignore[call-arg]


# Module-level settings instance, imported lazily in on_startup so that
# tests can patch 'heimdall.worker.settings' without triggering env-var
# validation at import time.
settings: Any = None


def main() -> None:
    """Console-script entrypoint: start the Arq worker with WorkerSettings.

    Invoked as ``heimdall-worker`` (see [project.scripts] in pyproject.toml)
    or directly with ``python -m heimdall.worker``.
    """
    from arq.worker import run_worker

    run_worker(WorkerSettings)  # type: ignore[arg-type]


class WorkerSettings:
    """Arq WorkerSettings: registers run_review and wires startup/shutdown.

    Launch the worker process with:
        arq heimdall.worker.WorkerSettings
    """

    functions = [run_review]
    # RedisSettings is initialised from env at worker-launch time via on_startup;
    # the default here points to localhost so the class attribute is always a
    # valid RedisSettings instance (Arq will use it if not overridden).
    redis_settings: RedisSettings = RedisSettings()

    @staticmethod
    async def on_startup(ctx: dict[str, Any]) -> None:
        """Open the database and store app credentials in ctx.

        Reads Settings from the environment, overrides redis_settings on the
        class, then populates ctx with:
            db:                     initialised Database instance
            app_id:                 GitHub App numeric ID
            private_key:            PEM-encoded RSA private key
            claude_binary:          path/name of the claude CLI
            lens_token_cap:         per-agent cumulative-token cap
            lens_timeout_seconds:   per-lens wall-clock timeout
            review_timeout_seconds: per-review wall-clock timeout (pipeline-wide)
            debug_logging:          log findings/code text when True
        """
        global settings
        if settings is None:
            settings = _load_settings()

        # Update redis_settings from the live config so the running worker uses
        # the correct Redis URL even if the default was overridden in .env.
        WorkerSettings.redis_settings = RedisSettings.from_dsn(settings.redis_url)

        db = Database(_db_path_from_url(settings.database_url))
        await db.initialize()
        ctx["db"] = db
        ctx["app_id"] = settings.github_app_id
        ctx["private_key"] = settings.github_app_private_key
        ctx["claude_binary"] = settings.claude_binary
        ctx["lens_token_cap"] = settings.lens_token_cap
        ctx["lens_timeout_seconds"] = settings.lens_timeout_seconds
        ctx["review_timeout_seconds"] = settings.review_timeout_seconds
        ctx["debug_logging"] = settings.debug_logging

    @staticmethod
    async def on_shutdown(ctx: dict[str, Any]) -> None:
        """Close the database connection."""
        db: Database = ctx["db"]
        await db.close()
