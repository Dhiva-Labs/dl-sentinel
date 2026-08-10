"""Fixture module with no known insecure patterns; a negative control for
DL Sentinel scanner tests. Not a real application.
"""

import hashlib
import os
import subprocess


def run_user_report(username):
    # Safe: fixed executable, arguments passed as a list — no shell.
    return subprocess.check_output(["report-tool", "--user", username, "--format", "json"])


def find_user_by_name(cursor, name):
    # Safe: parameterized query.
    return cursor.execute("SELECT * FROM users WHERE name = %s", (name,))


def hash_password(password, salt):
    # Safe: a key-derivation function suited to password hashing.
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=16384, r=8, p=1)


# Safe: configuration read from the environment, never hardcoded.
DATABASE_URL = os.environ.get("DATABASE_URL", "")
API_KEY = os.environ.get("API_KEY", "")
