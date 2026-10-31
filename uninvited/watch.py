"""`uninvited watch`: run the Temporal worker and start (or attach to) Night Watch."""

from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from . import config

WATCH_ID = "uninvited-night-watch"


def temporal_cli() -> str | None:
    return os.environ.get("UNINVITED_TEMPORAL_CLI") or shutil.which("temporal")


def start_dev_server(cli: str) -> None:
    """Start a local Temporal dev server that keeps its history next to Uninvited's data."""
    db = config.home() / "temporal.db"
    flags = 0x00000008 | 0x00000200 if os.name == "nt" else 0  # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
    subprocess.Popen([cli, "server", "start-dev", "--db-filename", str(db), "--ip", "127.0.0.1", "--log-level", "warn"],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=flags)


async def connect(autostart: bool = True):
    from temporalio.client import Client

    try:
        return await Client.connect(config.TEMPORAL_ADDRESS)
    except Exception:
        cli = temporal_cli()
        if not (autostart and cli):
            raise SystemExit(
                f"Can't reach Temporal at {config.TEMPORAL_ADDRESS}.\n"
                f"Install the Temporal CLI and run:  temporal server start-dev --db-filename \"{config.home() / 'temporal.db'}\"")
        print("Starting a local Temporal dev server (history is kept in temporal.db)...")
        start_dev_server(cli)
        for _ in range(40):
            await asyncio.sleep(1)
            try:
                return await Client.connect(config.TEMPORAL_ADDRESS)
            except Exception:
                continue
        raise SystemExit("The Temporal dev server did not come up.")


async def _run(args) -> int:
    from temporalio.common import WorkflowIDConflictPolicy
    from temporalio.worker import Worker

    from .watch_activities import explain_entry, list_pending, take_snapshot, write_night_report, WatchState
    from .watch_workflow import ExplainAll, NightWatch

    client = await connect()
    if args.status:
        state = await client.get_workflow_handle(WATCH_ID).query(NightWatch.status)
        print(f"Night Watch: {state.checks} checks since {state.started}; {state.exits} standby exits "
              f"({state.not_you} not you); {len(state.new_entries)} new entries.")
        return 0
    if args.stop:
        await client.get_workflow_handle(WATCH_ID).signal(NightWatch.stop)
        print("Asked Night Watch to stop after its current check.")
        return 0

    with ThreadPoolExecutor(max_workers=4) as pool:
        worker = Worker(client, task_queue=config.TASK_QUEUE, workflows=[NightWatch, ExplainAll],
                        activities=[take_snapshot, explain_entry, list_pending, write_night_report],
                        activity_executor=pool)
        async with worker:
            if args.explain_all:
                wid = f"uninvited-explain-all-{datetime.now():%Y%m%d-%H%M%S}"
                handle = await client.start_workflow(ExplainAll.run, id=wid, task_queue=config.TASK_QUEUE)
                print(f"Durable workflow {wid} started. Stop this process, Ollama or the laptop at any time:\n"
                      f"it resumes where it stopped. Temporal UI: http://localhost:8233")
                result = asyncio.ensure_future(handle.result())
                while not result.done():
                    await asyncio.sleep(3)
                    try:
                        p = await handle.query(ExplainAll.progress)
                        print(f"\r  {p['done']}/{p['total']} explained, {p['retried']} needed a retry   ", end="", flush=True)
                    except Exception:
                        pass
                print("\n", {k: v for k, v in result.result().items() if k != "products"})
                return 0
            if not args.worker_only:
                await client.start_workflow(NightWatch.run, WatchState(interval_minutes=args.interval), id=WATCH_ID,
                                            task_queue=config.TASK_QUEUE,
                                            id_conflict_policy=WorkflowIDConflictPolicy.USE_EXISTING)
                print(f"Night Watch is on duty (workflow '{WATCH_ID}', a check every {args.interval} min).\n"
                      "Close the lid whenever you like. Ctrl+C stops this worker; run the command again and the watch "
                      "continues from its last check.\nTemporal UI: http://localhost:8233")
            await asyncio.Event().wait()
    return 0


def main(args) -> int:
    try:
        return asyncio.run(_run(args))
    except KeyboardInterrupt:
        print("\nWorker stopped. The workflow is still recorded in Temporal; run the command again to resume.")
        return 0
