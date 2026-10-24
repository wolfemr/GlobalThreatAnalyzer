import sqlite3
from pathlib import Path

databasePath = Path("threat_analyzer.db")

def createDatabaseConnection(path: Path = databasePath) -> sqlite3.Connection:
    #Create the database connection
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn

def createTables(conn: sqlite3.Connection):
    cursor = conn.cursor()

    # Daily complete blacklist pull (/blacklist); 1 row per IP per day
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS blacklist_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL,
            country_code TEXT,
            abuse_confidence_score INTEGER,
            last_reported_at TEXT,
            collected_at TEXT NOT NULL
        );
    """)

    # IP Enrichment Summary (/check); 1 row per /check API call
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ip_enrichment (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL,
            checked_at TEXT NOT NULL,
            country_code TEXT,
            country_name TEXT,
            isp TEXT,
            domain TEXT,
            usage_type TEXT,
            is_tor BOOLEAN,
            is_whitelisted BOOLEAN,
            abuse_confidence_score INTEGER,
            total_reports INTEGER,
            num_distinct_users INTEGER,
            last_reported_at TEXT
        );
    """)

    # Reports; 1 row per entry, returned within /check API calls
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL,
            enrichment_id INTEGER NOT NULL,
            reported_at TEXT,
            reporter_id INTEGER,
            reporter_country_code TEXT,
            reporter_country_name TEXT,
            comment TEXT,
            FOREIGN KEY (enrichment_id) REFERENCES ip_enrichment(id)
        );
    """)

    #
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS report_categories (
            report_id INTEGER NOT NULL,
            category_id INTEGER NOT NULL,
            FOREIGN KEY (report_id) REFERENCES reports (id),
            PRIMARY KEY (report_id, category_id)
        );
    """)

    conn.commit()

def main():
    conn = createDatabaseConnection()
    try:
        createTables(conn)
        print(f"Database created successfully at: {databasePath.resolve()}")
    finally:
        conn.close()


if __name__ == "__main__":
    main()