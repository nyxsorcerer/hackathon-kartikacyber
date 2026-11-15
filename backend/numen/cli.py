import argparse
import getpass
from psycopg import sql
from .config import Config, secret_env
from .db import make_database
from .domain import settings
from .models import LoginSession, Operator
from .security import hash_password
from sqlalchemy import delete

INGRESS_ROLES = {
    "asset_monitor_push": "NUMEN_PUSH_DATABASE_PASSWORD",
    "asset_monitor_agent": "NUMEN_AGENT_DATABASE_PASSWORD",
}


def ingress_roles(db, passwords):
    """Creates each missing role and gives it LOGIN, its password and its limits. Grants nothing:
    each migration grants on the tables it adds. Composed with psycopg.sql, as a password may hold
    ':' or '%'."""
    with db.connection().connection.cursor() as cursor:
        for role, password in passwords.items():
            name, literal = sql.Identifier(role), sql.Literal(role)
            cursor.execute(sql.SQL(
                "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = {})"
                " THEN CREATE ROLE {} NOLOGIN; END IF; END $$"
            ).format(literal, name))
            cursor.execute(sql.SQL("ALTER ROLE {} WITH LOGIN PASSWORD {} CONNECTION LIMIT 5").format(
                name, sql.Literal(password)))
            cursor.execute(sql.SQL("ALTER ROLE {} SET statement_timeout = '5s'").format(name))


def main():
    parser = argparse.ArgumentParser(description="Container-based Numen operator setup/recovery")
    parser.add_argument("command", choices=["bootstrap", "reset-password", "ingress-roles"])
    args = parser.parse_args()
    if args.command == "ingress-roles":
        passwords = {role: secret_env(name) for role, name in INGRESS_ROLES.items()}
        if not all(passwords.values()):
            raise SystemExit(" and ".join(INGRESS_ROLES.values()) + " must be set: run make init")
        _, factory = make_database(Config.from_env())
        with factory.begin() as db:
            ingress_roles(db, passwords)
        print("Ingress database roles configured")
        return
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
    print("Operator configured; previous sessions revoked")


if __name__ == "__main__":
    main()
