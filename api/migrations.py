import logging
import os
import sqlite3
import sys


def migrate(db: sqlite3.Connection):
    migrations_cursor = db.cursor()
    with open("migrations/init.sql", "r") as f:
        migrations_cursor.execute(f.read())
        migrations_cursor.connection.commit()

    migrations = os.listdir("migrations")
    migrations.remove("init.sql")
    for m in migrations:
        n = m.split(".")[0]
        try:
            n = int(n)
        except Exception:
            print("Долбогном :3")
            sys.exit(-1)

        exists = migrations_cursor.execute(
            "SELECT * FROM migrations WHERE id = ?", (n,)
        )
        if not exists.fetchone():
            with open(f"migrations/{m}", "r") as f:
                migrations_cursor.execute(f.read())
                migrations_cursor.execute("INSERT INTO migrations(id) VALUES (?)", (n,))
                migrations_cursor.connection.commit()
                logging.info(f"Миграция {n} была выполнена")
        else:
            logging.info(f"Миграция {n} уже выполнена")
