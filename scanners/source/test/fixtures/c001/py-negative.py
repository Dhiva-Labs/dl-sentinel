import subprocess


def run_report_fixed():
    return subprocess.check_output("report-tool --user=fixed-account", shell=True)


def run_report_no_shell(username):
    cmd = "report-tool --user=" + username
    return subprocess.check_output(cmd)
