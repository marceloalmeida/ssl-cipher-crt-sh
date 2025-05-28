#!/usr/bin/env python3
# subdomain_enumeration.py

import sqlite3
import requests
import json
import time
from urllib.parse import quote

def setup_database():
    """Create the domain_names table if it doesn't exist"""
    conn = sqlite3.connect('domains.db')
    cursor = conn.cursor()

    # Create domain_names table
    cursor.execute('''
         CREATE TABLE IF NOT EXISTS tlds (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            known_subdomains TEXT DEFAULT '',
            skip_existing INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    ''')


    tlds = [
        {'tld': 'malmeida.dev', 'known_subdomains': 'www'}
    ]
    # Insert TLDs into the tlds table
    cursor.executemany('''
        INSERT OR IGNORE INTO tlds (name, known_subdomains, skip_existing) VALUES (?, ?, ?)
    ''', [(tld['tld'], tld.get('known_subdomains', ''), tld.get('skip_existing', 1)) for tld in tlds])

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS domain_names (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tld_id INTEGER,
            name_value TEXT NOT NULL UNIQUE,
            resolver_answer TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (tld_id) REFERENCES tlds (id)
            ON DELETE CASCADE
        );
    ''')

    conn.commit()
    return conn

def fetch_domains_from_crtsh(tld):
    """Fetch certificate data from crt.sh for a given TLD"""
    try:
        url = f"https://crt.sh/json?q={quote(tld)}"
        response = requests.get(url, timeout=30)
        response.raise_for_status()

        data = response.json()
        domains = set()

        for cert in data:
            if 'name_value' in cert:
                # Split multiple domains that might be in a single name_value
                name_values = cert['name_value'].split('\n')
                for domain in name_values:
                    domain = domain.strip()
                    if domain:
                        domains.add(domain)

        return list(domains)

    except requests.exceptions.RequestException as e:
        print(f"Error fetching data for {tld}: {e}")
        return []
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON for {tld}: {e}")
        return []

def resolve_domain(domain):
    """Resolve a domain to its IP address"""
    try:
        response = requests.get(f"https://dns.google/resolve?name={domain}", timeout=10)
        response.raise_for_status()
        data = response.json()
        if 'Answer' in data:
            return [answer['data'] for answer in data['Answer']]
        else:
            return []
    except requests.exceptions.RequestException as e:
        print(f"Error resolving {domain}: {e}")
        return []

def process_tlds():
    """Main function to process TLDs and store domain names"""
    conn = setup_database()
    cursor = conn.cursor()

    try:
        # Fetch all TLDs from the tlds table
        cursor.execute("SELECT id, name, known_subdomains FROM tlds")
        tlds = cursor.fetchall()

        print(f"Found {len(tlds)} TLDs to process")

        for tld_id, tld_name, tld_known_subdomain in tlds:
            print(f"Processing TLD: {tld_name}")

            # Check if we already have domains for this TLD
            cursor.execute("SELECT COUNT(*) FROM domain_names WHERE tld_id = ?", (tld_id,))
            existing_count = cursor.fetchone()[0]

            cursor.execute("SELECT skip_existing FROM tlds WHERE id = ?", (tld_id,))
            skip_existing = cursor.fetchone()[0]

            if skip_existing and existing_count > 0:
                print(f"  Skipping {tld_name} - already has {existing_count} domains")
                continue

            for known_subdomain in tld_known_subdomain.split(','):
                known_subdomain = known_subdomain.strip()
                if known_subdomain:
                    cursor.execute(
                        "INSERT OR IGNORE INTO domain_names (tld_id, name_value, resolver_answer) VALUES (?, ?, ?)",
                        (tld_id, known_subdomain + '.' + tld_name, json.dumps(resolve_domain(known_subdomain + '.' + tld_name)))
                    )
            conn.commit()

            # Fetch domains from crt.sh
            domains = fetch_domains_from_crtsh(tld_name)

            if domains:
                domain_data = [(tld_id, "WILDCARD" + domain[1:] if domain.startswith('*') else domain, json.dumps(resolve_domain("WILDCARD" + domain[1:] if domain.startswith('*') else domain))) for domain in domains]
                cursor.executemany(
                    "INSERT OR IGNORE INTO domain_names (tld_id, name_value, resolver_answer) VALUES (?, ?, ?)",
                    domain_data
                )
                conn.commit()
                print(f"  Added {len(domains)} domains for {tld_name}")
            else:
                print(f"  No domains found for {tld_name}")

            # Be respectful to the API - add a small delay
            time.sleep(2)

    except Exception as e:
        print(f"Error processing TLDs: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    process_tlds()
