import requests


def fetch_insecure(url):
    return requests.get(url, verify=False)
