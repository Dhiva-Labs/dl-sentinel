import subprocess


def run_report(username):
    cmd = "report-tool --user=" + username
    return subprocess.check_output(cmd, shell=True)
