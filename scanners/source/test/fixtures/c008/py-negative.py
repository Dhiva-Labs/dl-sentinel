import requests


def fetch_secure(url):
    return requests.get(url, verify=True)


def fetch_default(url):
    return requests.get(url)
