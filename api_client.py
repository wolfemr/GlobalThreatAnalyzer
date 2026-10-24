import os
import requests
import time
from dotenv import load_dotenv
from pathlib import Path


scriptPath = Path(__file__).resolve().parent
envPath = scriptPath / ".env"

# API key stored in .env
def loadApiKey():

    load_dotenv(dotenv_path=envPath)

    apiKey = os.getenv("ABUSEIPDB_API_KEY")
    if not envPath.exists():
        raise RuntimeError(
            f".env file not found in {scriptPath}. "
        )
    if not apiKey:
        raise RuntimeError(
            f"Api key not found in {envPath}. "
        )
    return apiKey


def fetchData(url: str, apiKey: str, params: dict, maxRetries: int = 3, timeout: int = 30) -> dict:

    headers = {
        "Key": apiKey,
        "Accept": "application/json",
    }

    lastError = None

    for attempt in range(maxRetries):
        try:
            response = requests.get(url, headers=headers, params=params, timeout=timeout)
            response.raise_for_status()
            return response.json()

        except requests.exceptions.HTTPError as e:
            statusCode = e.response.status_code if e.response is not None else None

            # Fail fast if response is in 400-level
            if statusCode is not None and 400 <= statusCode < 500:
                raise RuntimeError(
                    f"The request was rejected (HTTP {statusCode})"
                ) from e

            lastError = e

        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
            lastError = e

        if attempt < maxRetries - 1:
            waitSeconds = 2 ** attempt
            print(f"Attempt {attempt + 1} failed ({lastError}). "
                  f"Waiting {waitSeconds} seconds...")
            time.sleep(waitSeconds)

    raise RuntimeError(f"Failed to retrieve blacklist after {maxRetries} retries: {lastError}")
