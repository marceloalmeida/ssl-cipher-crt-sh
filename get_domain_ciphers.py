#!/usr/bin/env python3
# get-domain-ciphers.py

import subprocess
import shutil
import sys
import xml.etree.ElementTree as ET
import sqlite3
from concurrent.futures import ThreadPoolExecutor
import concurrent
import time


def setup_database():
    """Create the domain_names table if it doesn't exist"""
    conn = sqlite3.connect('domains.db')
    cursor = conn.cursor()

    # Create domain_names table
    cursor.execute('''
         CREATE TABLE IF NOT EXISTS ciphers (
            cipher_id TEXT PRIMARY KEY,
            sslversion TEXT NOT NULL,
            cipher_name TEXT NOT NULL,
            bits TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    ''')

    # Create table that maps domain names to ciphers
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS domain_ciphers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain_id INTEGER,
            cipher_id TEXT,
            FOREIGN KEY (domain_id) REFERENCES domain_names (id) ON DELETE CASCADE,
            FOREIGN KEY (cipher_id) REFERENCES ciphers (cipher_id) ON DELETE CASCADE
        );
    ''')

    conn.commit()
    return conn

def run_sslscan_xml(host, port=443):
    if not shutil.which("sslscan"):
        print("Error: sslscan is not installed or not in PATH.")
        sys.exit(1)

    command = ["sslscan", "--xml=-", "--show-cipher-ids", f"{host}:{port}"]

    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print("Error running sslscan:")
        print(e.stderr)
        sys.exit(1)

def extract_accepted_ciphers(xml_data):
    ciphers = []
    root = ET.fromstring(xml_data)

    for cipher in root.findall(".//cipher"):
        status = cipher.attrib.get("status")
        if status in {"accepted", "preferred"}:
            sslversion = cipher.attrib.get("sslversion", "")
            cipher_name = cipher.attrib.get("cipher", "")
            cipher_id = cipher.attrib.get("id", "")
            bits = cipher.attrib.get("bits", "")
            ciphers.append({
                "sslversion": sslversion,
                "cipher_name": cipher_name,
                "bits": bits,
                "cipher_id": cipher_id,
                "status": status
            })
    return ciphers

def insert_ciphers_to_db(ciphers, conn):
    cursor = conn.cursor()
    for cipher in ciphers:
        cursor.execute('''
            INSERT OR IGNORE INTO ciphers (cipher_id, sslversion, cipher_name, bits, status)
            VALUES (?, ?, ?, ?, ?)
        ''', (cipher['cipher_id'], cipher['sslversion'], cipher['cipher_name'], cipher['bits'], cipher['status']))
    conn.commit()

def map_domain_to_ciphers(host, ciphers, conn):
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM domain_names WHERE name_value = ?', (host,))
    domain_id = cursor.fetchone()

    if not domain_id:
        cursor.execute('INSERT INTO domain_names (name_value) VALUES (?)', (host,))
        domain_id = cursor.lastrowid
    else:
        domain_id = domain_id[0]

    for cipher in ciphers:
        cursor.execute('''
            INSERT OR IGNORE INTO domain_ciphers (domain_id, cipher_id)
            VALUES (?, ?)
        ''', (domain_id, cipher['cipher_id']))
    conn.commit()

def process_domain(conn, host, port=443):
    # skip if domain_ciphers already has entries for this host
    cursor = conn.cursor()
    cursor.execute('''
        SELECT count(1) FROM domain_ciphers dc
        LEFT JOIN domain_names dn ON dc.domain_id = dn.id
        LEFT JOIN tlds t ON dn.tld_id = t.id
        WHERE dn.name_value = ? AND t.skip_existing = 1
    ''', (host,))
    if cursor.fetchone()[0] > 0:
        print(f"Domain {host} already processed, skipping...")
        return []
    print(f"Processing {host}:{port} for SSL ciphers...")

    xml_output = run_sslscan_xml(host, port)
    ciphers = extract_accepted_ciphers(xml_output)
    if not ciphers:
        print(f"No accepted ciphers found for {host}:{port}.")
        return []
    insert_ciphers_to_db(ciphers, conn)
    map_domain_to_ciphers(host, ciphers, conn)

def process_domains():
    conn = setup_database()
    cursor = conn.cursor()

    cursor.execute("SELECT name_value FROM domain_names")
    domains = [row[0] for row in cursor.fetchall()]
    if not domains:
        print("No domains found in the database.")
        return
    print(f"Processing {len(domains)} domains for SSL ciphers...")

    # Function that wraps process_domain to use a separate connection for each thread
    def process_domain_wrapper(host, port=443):
        try:
            local_conn = sqlite3.connect('domains.db')
            result = process_domain(local_conn, host, port)
            local_conn.close()
            return host, True
        except Exception as e:
            print(f"Error processing {host}: {e}")
            return host, False

    # Set max_workers based on your system capabilities
    max_workers = min(32, len(domains))
    print(f"Using {max_workers} workers for parallel processing...")

    start_time = time.time()
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks
        futures = [executor.submit(process_domain_wrapper, host) for host in domains]

        # Process results as they complete
        completed = 0
        for future in concurrent.futures.as_completed(futures):
            completed += 1
            host, success = future.result()
            print(f"Processed {host} - {'Success' if success else 'Failed'} ({completed}/{len(domains)})")

    print(f"All domains processed in {time.time() - start_time:.2f} seconds")
    conn.close()

if __name__ == "__main__":
    process_domains()
