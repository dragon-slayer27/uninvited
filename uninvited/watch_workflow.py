"""Temporal workflows. Deterministic code only: all I/O happens in activities."""

from __future__ import annotations

import asyncio
from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy

with workflow.unsafe.imports_passed_through():
    from .watch_activities import (
        ExplainRequest,
        WatchState,
        explain_entry,
        list_pending,
        take_snapshot,
        write_night_report,
    )

# A local model can be slow, busy or not started yet: keep retrying with backoff, forever.
MODEL_RETRY = RetryPolicy(initial_interval=timedelta(seconds=15), backoff_coefficient=2.0,
                          maximum_interval=timedelta(minutes=5))
SCAN_RETRY = RetryPolicy(initial_interval=timedelta(seconds=10), backoff_coefficient=2.0,
                         maximum_interval=timedelta(minutes=2), maximum_attempts=10)


@workflow.defn
class NightWatch:
    def __init__(self) -> None:
        self._state = WatchState()
        self._stop = False

    @workflow.signal
    def stop(self) -> None:
        self._stop = True

    @workflow.query
    def status(self) -> WatchState:
        return self._state

    @workflow.run
    async def run(self, state: WatchState) -> WatchState:
        self._state = state
        if not state.started:
            state.started = workflow.now().isoformat()
        state.workflow_id = workflow.info().workflow_id
        while not self._stop:
            snap = await workflow.execute_activity(
                take_snapshot, state.last_event_time,
                start_to_close_timeout=timedelta(minutes=5), retry_policy=SCAN_RETRY)
            if state.checks > 0:  # the first check only sets the baseline
                known = set(state.known_ids)
                for entry_id in snap.entry_ids:
                    if entry_id in known:
                        continue
                    info = await workflow.execute_activity(
                        explain_entry, ExplainRequest(entry_id, "snapshot"),
                        start_to_close_timeout=timedelta(minutes=6), retry_policy=MODEL_RETRY)
                    state.new_entries.append(info)
                state.exits += len(snap.events)
                state.not_you += sum(1 for e in snap.events if e.get("class") != "you")
                state.events = (state.events + snap.events)[-200:]
            state.known_ids = snap.entry_ids
            state.last_event_time = snap.latest_event_time or state.last_event_time
            state.checks += 1
            await workflow.execute_activity(write_night_report, state,
                                            start_to_close_timeout=timedelta(minutes=1), retry_policy=SCAN_RETRY)
            if state.checks % 40 == 0:
                workflow.continue_as_new(state)
            try:
                await workflow.wait_condition(lambda: self._stop, timeout=timedelta(minutes=state.interval_minutes))
            except asyncio.TimeoutError:
                pass
        return state


@workflow.defn
class ExplainAll:
    """Explain every unexamined entry. If the worker, Ollama or the laptop goes down, it resumes where it stopped."""

    def __init__(self) -> None:
        self._done = 0
        self._total = 0
        self._current = ""
        self._retried = 0

    @workflow.query
    def progress(self) -> dict:
        return {"done": self._done, "total": self._total, "current": self._current, "retried": self._retried}

    @workflow.run
    async def run(self) -> dict:
        ids = await workflow.execute_activity(list_pending, start_to_close_timeout=timedelta(minutes=5),
                                              retry_policy=SCAN_RETRY)
        self._total = len(ids)
        names = []
        for entry_id in ids:
            self._current = entry_id
            info = await workflow.execute_activity(
                explain_entry, ExplainRequest(entry_id, "report"),
                start_to_close_timeout=timedelta(minutes=6), retry_policy=MODEL_RETRY)
            if info.get("attempt", 1) > 1:
                self._retried += 1
            names.append(info.get("product") or info.get("name") or entry_id)
            self._done += 1
        return {"explained": self._done, "needed_retries": self._retried, "products": names}
