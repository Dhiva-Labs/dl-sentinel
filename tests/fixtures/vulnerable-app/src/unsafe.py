"""Deliberately insecure fixture module for DL Sentinel scanner tests.

Not a real application; never imported or executed by anything.
"""

import hashlib
import ssl
import subprocess
import urllib.request


def run_user_report(username):
    # Insecure: shell command built via string concatenation from user input.
    cmd = "report-tool --user=" + username + " --format=json"
    return subprocess.check_output(cmd, shell=True)


def find_user_by_name(cursor, name):
    # Insecure: SQL built via string concatenation (SQL injection pattern).
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    return cursor.execute(query)


def hash_password(password):
    # Insecure: MD5 used to hash a password.
    return hashlib.md5(password.encode("utf-8")).hexdigest()


def fetch_insecure(url):
    # Insecure: TLS certificate verification disabled.
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return urllib.request.urlopen(url, context=ctx)


def run_expression(user_input):
    # Insecure: eval of externally-supplied input.
    return eval(user_input)


def read_user_temp(filename):
    # Insecure: hardcoded path traversal pattern into a temp directory.
    path = "/tmp/app-cache/../../etc/" + filename
    with open(path, "r") as fh:
        return fh.read()
