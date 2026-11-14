import time
from .broker import Broker
from .config import Config
from .db import make_database
from .domain import schedule, schedule_advisory_checks, schedule_served_checks
from .queue import recover


def main():
    config = Config.from_env()
    _, factory = make_database(config)
    broker = Broker(config)
    while True:
        recover(factory, broker)
        with factory.begin() as db:
            schedule(db)
        with factory.begin() as db:
            schedule_advisory_checks(db)
        with factory.begin() as db:
            schedule_served_checks(db)
        time.sleep(15)


if __name__ == "__main__":
    main()
