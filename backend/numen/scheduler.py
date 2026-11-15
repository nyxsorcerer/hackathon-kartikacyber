import time
from . import artifacts, servers
from .broker import Broker
from .config import Config
from .db import make_database
from .domain import (
    nudge_push_deliveries, prune_transcripts, schedule, schedule_advisory_checks, schedule_served_checks,
)
from .queue import recover


def prune(config, factory):
    """Transcript retention (A14). The rows go first, in one transaction, then their files, so no
    row ever names a removed file."""
    with factory.begin() as db:
        revisions = prune_transcripts(db)
    artifacts.remove_revisions(config.artifact_root, revisions)


def main():
    config = Config.from_env()
    _, factory = make_database(config)
    broker = Broker(config)
    next_prune = 0.0
    while True:
        recover(factory, broker)
        with factory.begin() as db:
            schedule(db)
        with factory.begin() as db:
            nudge_push_deliveries(db)  # B02
        servers.process_agent_requests(factory, config.artifact_root)  # B04
        with factory.begin() as db:
            schedule_advisory_checks(db)
        with factory.begin() as db:
            schedule_served_checks(db)
        if time.monotonic() >= next_prune:
            prune(config, factory)
            next_prune = time.monotonic() + 3600
        time.sleep(15)


if __name__ == "__main__":
    main()
