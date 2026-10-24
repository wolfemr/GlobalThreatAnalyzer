"""
Randomly select a subset of IP addresses from countries with a minimum of 3 reports, not proportionally, from the day's blacklist
"""

import pandas as pd
import random
import sqlite3
from pathlib import Path

databasePath = Path(__file__).resolve().parent / "threat_analyzer.db"

defaultQuota = 500
defaultMinPerCountry = 3


"""
Choose IP addresses  to pass to /check endpoint with the following criteria:
 - were collected the same day as the blacklist
 - have not already been enriched (not in ip_enrichment table)
"""
def selectDailySample(conn: sqlite3.Connection, collectedAt: str, quota: int = 500,
                      minPerCountry: int = 3, seed: int = 37) -> list[str]:

    query = """
        SELECT ip_address, country_code FROM blacklist_snapshots
        WHERE collected_at = ? AND ip_address NOT IN (SELECT ip_address FROM ip_enrichment)
    """

    #define dataframe
    df = pd.read_sql_query(query, conn, params=(collectedAt,))

    if df.empty:
        print(f"No un-enriched IP addresses found for {collectedAt}.")
        return []

    totalCount = len(df)
    selectedIps: list[str] = []

    for country_code, group in df.groupby("country_code"):

        # Given country's share of daily blacklist scaled to quota
        proportionalShare = (len(group) / totalCount) * quota

        n = max(minPerCountry, round(proportionalShare)) #apply floor
        n = min(n, len(group)) # apply ceiling

        sampled = group.sample(n=n, random_state=seed)
        selectedIps.extend(sampled["ip_address"].tolist())

    if len(selectedIps) > quota:
        random.seed(seed)
        selectedIps = random.sample(selectedIps, quota)


    return selectedIps

