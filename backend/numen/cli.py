import argparse
import getpass
from .config import Config, secret_env
from .db import make_database
from .domain import plugin_records, settings
from .models import LoginSession, Operator
from .security import hash_password
from sqlalchemy import delete


def main():
    parser = argparse.ArgumentParser(description="Container-based Numen operator setup/recovery")
    parser.add_argument("command", choices=["bootstrap", "reset-password"])
    args = parser.parse_args()
    config = Config.from_env()
    _, factory = make_database(config)
    password = secret_env("NUMEN_ADMIN_PASSWORD") or getpass.getpass(
        "New operator password (12+ characters): "
    )
    with factory.begin() as db:
        operator = db.get(Operator, "admin")
        if operator and args.command == "bootstrap":
            print("Operator already exists; use reset-password for recovery")
            return
        if operator:
            operator.password_hash = hash_password(password)
        else:
            db.add(Operator(id="admin", password_hash=hash_password(password)))
        db.execute(delete(LoginSession))
        settings(db, config)
        plugin_records(db)
    print("Operator configured; previous sessions revoked")


if __name__ == "__main__":
    main()
