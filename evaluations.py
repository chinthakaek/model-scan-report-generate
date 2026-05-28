import os
import requests
from dotenv import load_dotenv

load_dotenv()

TOKEN_URL = "https://auth.apps.paloaltonetworks.com/oauth2/access_token"

# This base URL is VERIFIED (used successfully by get_scan)
AIMS_BASE_URL = "https://api.sase.paloaltonetworks.com/aims"


class AimsApiError(RuntimeError):
    pass


def get_access_token() -> str:
    """
    Obtain OAuth2 access token using client credentials.
    """
    payload = {
        "grant_type": "client_credentials",
        "client_id": os.environ["MODEL_SECURITY_CLIENT_ID"],
        "client_secret": os.environ["MODEL_SECURITY_CLIENT_SECRET"],
        "scope": f"tsg_id:{os.environ['TSG_ID']}",
    }

    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }

    response = requests.post(
        TOKEN_URL,
        data=payload,
        headers=headers,
        timeout=30,
    )

    try:
        response.raise_for_status()
    except requests.HTTPError as e:
        raise AimsApiError(
            f"Token request failed ({response.status_code}): {response.text}"
        ) from e

    return response.json()["access_token"]


def get_scan_evaluations(scan_id: str) -> dict:
    """
    Fetch rule evaluations for a completed scan.

    IMPORTANT:
    As of now, the AIMS API DOES NOT expose a public
    /scans/{id}/evaluations

    This function is intentionally explicit and debuggable.
    """
    token = get_access_token()

    # 🚨 Endpoint is intentionally explicit and visible
    url = f"{AIMS_BASE_URL}/data/v1/scans/{scan_id}/evaluations?skip=0&limit=100"

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }

    response = requests.get(url, headers=headers, timeout=30)

    if response.status_code == 404:
        raise AimsApiError(
            "evaluations endpoint not found (404).\n"
            "This confirms that rule evaluations are NOT exposed via a public REST API.\n"
            "They are currently only visible via the UI / internal services.\n\n"
            f"Attempted URL:\n{url}"
        )

    try:
        response.raise_for_status()
    except requests.HTTPError as e:
        raise AimsApiError(
            f"Failed to fetch scan violations "
            f"({response.status_code}): {response.text}"
        ) from e

    return response.json()
