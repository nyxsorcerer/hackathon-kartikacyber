"""The only target HTTP interface exposed to generated version recipes."""
import os
import httpx

def fetch(url, method="GET"):
    with httpx.Client(trust_env=False, timeout=20) as client:
        response = client.post(os.environ["NUMEN_FETCH_URL"], headers={"X-Fetch-Token": os.environ["NUMEN_FETCH_TOKEN"]}, json={"url":url, "method":method})
        response.raise_for_status()
        return response.json()
