import argparse
import json
import sqlite3
import sys
import time

import ip_sample_selector
from api_client import loadApiKey, fetchData
from datetime import datetime, timezone
from pathlib import Path
from ip_sample_selector import selectDailySample

scriptPath = Path(__file__).resolve().parent
databasePath = scriptPath / "threat_analyzer.db"
rawDataPath = scriptPath / "rawData" / "checkIp"

# AbuseIPDB URL for /check API endpoint to gather reports on specific IP addresses
checkEndpointUrl = "https://api.abuseipdb.com/api/v2/check"

# Total check failures before aborting IP check attempt to save time and rate limit
maximumConsecutiveFailures = 5

# Call AbuseIPDB api /check endpoint from api_client.fetchData and return .json
def fetchIpDetails(apiKey: str, ip_address: str) -> dict:

    # required params for /check endpoint: ipAddress
    # optional params for /check endpoint: maxAgeInDays (default 30)
    # verbose (true/false, more detail such as attack type)
    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": 30,
        "verbose": "true",
    }
    return fetchData(checkEndpointUrl, apiKey, params)


def saveRawResponse(ipAddress: str, response: dict, collected_at: str,  ) -> None:

    rawDataPath.mkdir(parents=True, exist_ok=True)
    rawDataFilename = rawDataPath / f"IpAddressReports_{collected_at}.json"

    record = {
        "ip_address": ipAddress,
        "response": response
    }

    # Append instead of overwrite response file. Fault-tolerant in case of failure during API calls
    with open(rawDataFilename, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")
        f.flush()


# Parse check .json and write data to ip_enrichment DB table
def insertIpAddressData(conn: sqlite3.Connection, ipAddress: str, checkedAt: str, data: dict) -> int:

    data = data.get("data", {})
    cursor = conn.cursor()

    cursor.execute("""
      INSERT INTO ip_enrichment(
          ip_address, checked_at, country_code, country_name, isp, domain,
          usage_type, is_tor, is_whitelisted, abuse_confidence_score,
          total_reports, num_distinct_users, last_reported_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """,(
            ipAddress,
            checkedAt,
            data.get("countryCode"),
            data.get("countryName"),
            data.get("isp"),
            data.get("domain"),
            data.get("usageType"),
            data.get("isTor"),
            data.get("isWhitelisted"),
            data.get("abuseConfidenceScore"),
            data.get("totalReports"),
            data.get("numDistinctUsers"),
            data.get("lastReportedAt"),
    ))

    # get ID of inserted row
    enrichmentId = cursor.lastrowid

    reports = data.get("reports", [])
    for report in reports:
        cursor.execute("""
            INSERT INTO reports (
                ip_address, enrichment_id, reported_at, reporter_id, 
                reporter_country_code, reporter_country_name, comment
            ) VALUES (?, ?, ?, ?, ?, ?, ?) 
        """,(
            ipAddress,
            enrichmentId,
            report.get("reportedAt"),
            report.get("reporterId"),
            report.get("reporterCountryCode"),
            report.get("reporterCountryName"),
            report.get("comment"),
        ))
        reportId = cursor.lastrowid

        reportCategories = report.get("categories", [])
        for categoryId in reportCategories:
            cursor.execute("""
                INSERT INTO report_categories (report_id, category_id)
                VALUES (?, ?)
            """, (reportId, categoryId))

    return enrichmentId


def main():
    # Define some arguments to pass to the functions that will select the daily sample of IP addresses
    # to expand.
    parser = argparse.ArgumentParser(description="Fetches details of reported IP addresses from the "
                                                 "AbuseIPDB /check endpoint.")
    parser.add_argument(
        "--collected-at",
        type=str,
        default=None,
        help="Defines which day's blacklist to sample from."
    )

    parser.add_argument("--quota",
        type=int,
        default=ip_sample_selector.defaultQuota,
        help="The number of IP addresses to fetch expanded data on."
        )

    parser.add_argument("--min-per-country",
        type=int,
        default=ip_sample_selector.defaultMinPerCountry,
        help="The minimum number of IP addresses to fetch per country."
    )
    args = parser.parse_args()

    collectedAt = args.collected_at or datetime.now(timezone.utc).strftime("%Y-%m-%d")

    try:
        apiKey = loadApiKey()
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    conn = sqlite3.connect(databasePath)
    conn.execute("PRAGMA foreign_keys = ON")

    dailySample = selectDailySample(
        conn, collectedAt=collectedAt, quota=args.quota, minPerCountry=args.min_per_country
    )
    if not dailySample:
        print("No data to expand. Exiting.")
        conn.close()
        return

    print(f"Expanding {len(dailySample)} IP addresses for {collectedAt}.")

    rawIpCheckData = rawDataPath / f"IP_checks_{collectedAt}.jsonl"

    successCount = 0
    failureCount = 0
    consecutiveFailures = 0

    for i, ipAddress in enumerate(dailySample, start=1):
        checkedAt = datetime.now(timezone.utc).isoformat()

        try:
            response = fetchIpDetails(apiKey, ipAddress)

            # save backup copy of data in case db insertion fails
            saveRawResponse(ipAddress, response, collectedAt)

            insertIpAddressData(conn, ipAddress, checkedAt, response)
            conn.commit()

            successCount += 1
            consecutiveFailures = 0 # reset on successful attempt

        except RuntimeError as e:
            print(f" [{i}/{len(dailySample)}] Failed to check {ipAddress}: {e}")
            failureCount += 1
            consecutiveFailures += 1

            if consecutiveFailures >= maximumConsecutiveFailures:
                print(f"\n{consecutiveFailures} consecutive failures. Aborting.")
                break

        # Update progress every 50 attempts
        if i % 50 == 0:
            print(f" {i}/{len(dailySample)} IP addresses checked. ({successCount} successful, {failureCount} failed)")

        # Short pause between calls to not hammer the API
        time.sleep(.5)

    conn.close()

    print(f"\n Completed. {successCount} IPs checked successfully, {failureCount} failed.")
    print(f"Responses saved to {rawIpCheckData}")


if __name__=="__main__":
    main()