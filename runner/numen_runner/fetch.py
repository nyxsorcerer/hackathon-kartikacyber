"""The only target HTTP interface exposed to generated version recipes."""
import os
import httpx

def fetch(url, method="GET", user_agent=None):
    """user_agent names one of the gateway's fixed pair (A10); None keeps the version-fetch agent."""
    body = {"url":url, "method":method, **({"user_agent":user_agent} if user_agent is not None else {})}
    with httpx.Client(trust_env=False, timeout=20) as client:
        response = client.post(os.environ["NUMEN_FETCH_URL"], headers={"X-Fetch-Token": os.environ["NUMEN_FETCH_TOKEN"]}, json=body)
        response.raise_for_status()
        return response.json()
