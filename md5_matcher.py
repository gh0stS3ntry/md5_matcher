#!/usr/bin/env python3

import os
import sys
import csv
import argparse
import time
import sqlite3
import requests
import re
from collections import defaultdict
from datetime import datetime

def load_bad_hashes(filepath: str) -> set:
    """Loads known bad hashes into a set for O(1) lookups."""
    bad_hashes = set()
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                clean_hash = line.strip().lower()
                if len(clean_hash) == 32:
                    bad_hashes.add(clean_hash)
    except Exception as e:
        print(f"[!] Error loading bad hashes: {e}", file=sys.stderr)
        sys.exit(1)
    return bad_hashes

def init_db(db_path: str) -> sqlite3.Connection:
    """Initializes the SQLite database and creates the cache table."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS vt_cache (
            md5 TEXT PRIMARY KEY,
            verdict TEXT,
            link TEXT,
            timestamp DATETIME
        )
    ''')
    conn.commit()
    return conn

def check_cache(cursor: sqlite3.Cursor, md5: str) -> tuple:
    """Checks the local SQLite database for a previously queried hash."""
    cursor.execute('SELECT verdict, link FROM vt_cache WHERE md5 = ?', (md5,))
    return cursor.fetchone()

def update_cache(conn: sqlite3.Connection, md5: str, verdict: str, link: str):
    """Saves a new VT verdict into the local DB."""
    cursor = conn.cursor()
    cursor.execute('''
        INSERT OR REPLACE INTO vt_cache (md5, verdict, link, timestamp)
        VALUES (?, ?, ?, ?)
    ''', (md5, verdict, link, datetime.now()))
    conn.commit()

def query_virustotal(session: requests.Session, api_key: str, file_hash: str) -> tuple:
    """Queries VT for a hash and returns the verdict and analysis link."""
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}
    
    try:
        response = session.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            total_engines = sum(stats.values())
            malicious_count = stats.get('malicious', 0)
            verdict = f"Malicious: {malicious_count} / {total_engines}"
            link = f"https://www.virustotal.com/gui/file/{file_hash}"
            return verdict, link
            
        elif response.status_code == 404:
            return "Not Found", "https://www.virustotal.com/gui/file/" + file_hash
        elif response.status_code == 429:
            return "Rate Limited (429)", "N/A"
        elif response.status_code == 401:
            return "Unauthorized (Check API Key)", "N/A"
        else:
            return f"HTTP {response.status_code}", "N/A"
            
    except requests.exceptions.RequestException:
        return "Connection Error", "N/A"

def main():
    parser = argparse.ArgumentParser(description="Extract hashes from files, match against known-bad list, and enrich via VT.")
    parser.add_argument("-f", "--files", required=True, help="Comma-separated list of files containing hashes to check")
    parser.add_argument("-b", "--badlist", required=True, help="Text file containing known bad MD5 hashes")
    parser.add_argument("-o", "--output", default="enriched_ioc_results.csv", help="Output CSV file path")
    parser.add_argument("-c", "--cache", default="vt_cache.db", help="Path to SQLite cache database")
    parser.add_argument("--sleep", type=float, default=15.0, help="Seconds to sleep between VT API calls")
    
    args = parser.parse_args()

    api_key = os.environ.get("VT_API_KEY")
    if not api_key:
        print("[!] ERROR: VT_API_KEY environment variable is not set.", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Loading known bad hashes from {args.badlist}...")
    bad_hashes = load_bad_hashes(args.badlist)

    # 1. Deduplication Phase
    # We use a defaultdict of sets to map: hash -> set(file1, file2)
    # This guarantees we NEVER query VT twice for the same hash in a single run.
    hash_to_files = defaultdict(set)
    md5_regex = re.compile(r'\b([a-fA-F0-9]{32})\b')
    target_files = [f.strip() for f in args.files.split(',')]

    print(f"[*] Parsing target files and deduplicating hashes...")
    for filepath in target_files:
        if not os.path.isfile(filepath):
            print(f"[-] Warning: '{filepath}' not found. Skipping.", file=sys.stderr)
            continue
        
        filename = os.path.basename(filepath)
        try:
            with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    for raw_hash in md5_regex.findall(line):
                        hash_to_files[raw_hash.lower()].add(filename)
        except Exception as e:
            print(f"[!] Error reading '{filepath}': {e}", file=sys.stderr)

    unique_hash_count = len(hash_to_files)
    print(f"[*] Extraction complete. Found {unique_hash_count} unique hashes.")
    
    # 2. Setup Cache & VT Session
    db_conn = init_db(args.cache)
    db_cursor = db_conn.cursor()
    session = requests.Session()

    # 3. Enrichment & Output Phase
    print(f"[*] Starting triage and VT enrichment. Saving to {args.output}...")
    with open(args.output, mode='w', newline='', encoding='utf-8') as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(["Hash", "File containing the hash", "Match Known Bad (Y/N)", "Cached (Y/N)", "VT Verdict", "Link to VT Results"])

        for i, (md5_hash, origin_files) in enumerate(hash_to_files.items(), start=1):
            sys.stdout.write(f"\r[*] Processing {i}/{unique_hash_count} ({(i/unique_hash_count)*100:.1f}%) -> {md5_hash}")
            sys.stdout.flush()

            # Check Known Bad
            is_bad = "Y" if md5_hash in bad_hashes else "N"

            # Check Local SQLite Cache
            cached_result = check_cache(db_cursor, md5_hash)
            if cached_result:
                is_cached = "Y"
                verdict, link = cached_result
            else:
                is_cached = "N"
                # Query VirusTotal
                verdict, link = query_virustotal(session, api_key, md5_hash)
                
                # Save to cache if it's a valid response
                if "Rate Limited" not in verdict and "Unauthorized" not in verdict and "Connection Error" not in verdict:
                    update_cache(db_conn, md5_hash, verdict, link)
                
                # Throttle API calls
                if "Rate Limited" not in verdict:
                    time.sleep(args.sleep)

            # Write rows for each file this hash was found in
            # If the hash was in 3 files, it creates 3 rows in the CSV, but only took 1 API call.
            for origin_file in origin_files:
                writer.writerow([md5_hash, origin_file, is_bad, is_cached, verdict, link])
            
            # Flush buffer so you can watch the CSV populate in real-time
            csv_file.flush()

    db_conn.close()
    print(f"\n[*] Scan complete. Results saved to {args.output}")

if __name__ == "__main__":
    main()
