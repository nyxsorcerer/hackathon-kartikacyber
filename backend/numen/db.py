from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from .models import Base, Setting


def make_database(config, initialize=False):
    engine = create_engine(
        config.database_url,
        pool_pre_ping=True,
        connect_args={"check_same_thread": False}
        if config.database_url.startswith("sqlite")
        else {},
    )
    if engine.dialect.name == "sqlite":

        @event.listens_for(engine, "connect")
        def fk(dbapi, _):
            dbapi.execute("PRAGMA foreign_keys=ON")

    if initialize:
        Base.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    if initialize:
        with factory.begin() as db:
            if not db.get(Setting, "global"):
                db.add(
                    Setting(
                        id="global",
                        data={
                            "monitor_interval_days": config.monitor_interval_days,
                            "default_profiles": {},
                            "webhook_enabled": False,
                            "dashboard_url": "",
                        },
                    )
                )
    return engine, factory
