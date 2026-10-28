"""Safe controls should not match the targeted insecure patterns."""
import hashlib
import sqlite3
import subprocess
import yaml

def query(db: sqlite3.Connection, name: str):
    return db.execute("SELECT name FROM items WHERE name = ?", (name,)).fetchall()

def command(value: str):
    return subprocess.run(["echo", value], shell=False, capture_output=True)

def parse_yaml(value: str):
    return yaml.safe_load(value)

def digest(value: str):
    return hashlib.sha256(value.encode()).hexdigest()
