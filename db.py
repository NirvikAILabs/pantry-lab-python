"""The database: SQLite, built into Python. Deleting pantry.db (python reset.py)
starts again with the sample data."""

import hashlib
import os
import secrets
import sqlite3

db = sqlite3.connect(os.environ.get("PANTRY_DB", "pantry.db"), check_same_thread=False)
db.row_factory = sqlite3.Row
db.executescript(
    """
    create table if not exists users (
      id integer primary key,
      email text unique not null,
      name text not null,
      password_hash text not null,
      is_admin integer not null default 0
    );
    create table if not exists sessions (
      id text primary key,
      user_id integer not null,
      csrf text,
      created_at text not null default current_timestamp
    );
    create table if not exists recipes (
      id integer primary key,
      owner_id integer not null,
      title text not null,
      body text not null,
      private integer not null default 0
    );
    create table if not exists comments (
      id integer primary key,
      recipe_id integer not null,
      user_id integer not null,
      body text not null
    );
    """
)


def seed(hash_password):
    """The sample data. `hash_password` is the app's own hashing function."""
    if db.execute("select count(*) from users").fetchone()[0] > 0:
        return
    users = [
        ("alice@pantry.test", "Alice", hash_password("alice-pantry-2026"), 1),
        ("bob@pantry.test", "Bob", hash_password("bob-pantry-2026"), 0),
    ]
    db.executemany("insert into users (email, name, password_hash, is_admin) values (?, ?, ?, ?)", users)
    recipes = [
        (1, "Secret family curry", "Grandma’s recipe. Never share the spice mix: 2 tsp garam masala, 1 tsp kasuri methi.", 1),
        (1, "Lemon rice", "Cooked rice, lemon, peanuts, curry leaves, mustard seeds, turmeric.", 0),
        (2, "Masala chai", "Tea, milk, ginger, cardamom, sugar. Boil, simmer, strain.", 0),
        (2, "Bob’s private shopping list", "Buy a birthday gift for Alice. Do not let her see this!", 1),
    ]
    db.executemany("insert into recipes (owner_id, title, body, private) values (?, ?, ?, ?)", recipes)
    db.commit()


# Password hashing used by the two versions of the app.
def sha256(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


# scrypt settings from the OWASP Password Storage Cheat Sheet (128 MiB of memory).
SCRYPT = {"n": 2**17, "r": 8, "p": 1, "maxmem": 256 * 1024 * 1024, "dklen": 64}


def scrypt_hash(password: str) -> str:
    salt = secrets.token_bytes(16)
    key = hashlib.scrypt(password.encode(), salt=salt, **SCRYPT)
    return f"scrypt${salt.hex()}${key.hex()}"
