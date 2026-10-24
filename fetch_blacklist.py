import argparse
import json
import sqlite3
import sys
from api_client import loadApiKey, fetchData
from datetime import datetime, timezone
from pathlib import Path

scriptPath = Path(__file__).resolve().parent
databasePath = scriptPath / "threat_analyzer.db"
rawDataPath = scriptPath / "rawData" / "blacklist"

# AbuseIPDB URL for /blacklist API endpoint to gather reported IP addresses
blacklistEndpointUrl = "https://api.abuseipdb.com/api/v2/blacklist"


# Call AbuseIPDB api /blacklist endpoint from api_client.fetchData and return .json
def fetchBlacklist(apiKey: str) -> dict:

    # Optional. Free tier defaults to 100 confidence score, but could specify with paid plans
    params = {
        "confidenceMinimum": 90,
    }

    return fetchData(blacklistEndpointUrl, apiKey, params)


# Save raw .json to disk as a backup incase db write fails
def saveRawData(data: dict, collected_at: str) -> Path:

    rawDataPath.mkdir(parents=True, exist_ok=True)
    rawDataFilename = rawDataPath / f"blacklist_{collected_at}.json"

    with open(rawDataFilename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    return rawDataFilename


# Parse blacklist .json and write data to blacklist_snapshots DB table
def insertBlacklistData(conn: sqlite3.Connection, data: dict, collectedAt: str) -> int:

    dataToInsert = data.get("data", [])
    if not dataToInsert:
        print("No data found in the API response.")
        return 0

    rowsToInsert = [
        (
            entry.get("ipAddress"),
            entry.get("countryCode"),
            entry.get("abuseConfidenceScore"),
            entry.get("lastReportedAt"),
            collectedAt,
        )
        for entry in dataToInsert
    ]

    insertQuery = """
        INSERT INTO blacklist_snapshots
            (ip_address, country_code, abuse_confidence_score, last_reported_at, collected_at)
        VALUES (?, ?, ?, ?, ?)
    """

    cursor = conn.cursor()
    cursor.executemany(insertQuery, rowsToInsert)
    conn.commit()

    return len(rowsToInsert)


def main():
    parser = argparse.ArgumentParser(description="Fetch and store blacklist data")
    parser.add_argument(
        "--collected-at",
        type=str,
        default=None,
        help="Datestamp for collection date, YYYY-MM-DD.",
    )
    args = parser.parse_args()

    collected_at = args.collected_at or datetime.now(timezone.utc).strftime("%Y-%m-%d")

    try:
        apiKey = loadApiKey()

        print("Fetching blacklist data for {collected_at}...")
        data = fetchBlacklist(apiKey)

        rawDataFilename = saveRawData(data, collected_at)
        print(f"Raw data saved to {rawDataPath} as {rawDataFilename}.")

        conn = sqlite3.connect(databasePath)
        conn.execute("PRAGMA foreign_keys = ON;")
        try:
            count = insertBlacklistData(conn, data, collected_at)
            print(f"Inserted {count} rows into blacklist_snapshots (collected at {collected_at}).")
        finally:
            conn.close()

        # Report any errors
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
