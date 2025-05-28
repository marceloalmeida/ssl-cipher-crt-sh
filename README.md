# Domain Enumeration

A collection of scripts for domain enumeration and reconnaissance.

## Description

This repository contains tools and scripts designed to facilitate domain enumeration tasks. Domain enumeration is the process of gathering information about domains, subdomains, and related network infrastructure to understand the attack surface of a target organization.

## Installation

```bash
# Clone the repository
git clone https://github.com/marceloalmeida/domain-enumeration.git

# Navigate to the directory
cd domain-enumeration

# Install dependencies (if any)
# pip install -r requirements.txt
```

## Scripts

### subdomain_enumeration.py

Identifies subdomains for a given domain using various techniques.

```bash
python3 subdomain_enumeration.py
```

### get-domain-ciphers.py
Performs DNS lookups and resolves hostnames to IP addresses.

```bash
python3 get-domain-ciphers.py
```

## Usage Examples

### Run all
```bash
# Run a full enumeration on a domain
./run_all.sh
```

### Connect to the database
```bash
sqlite3 domains.db
```

### Sample queries

#### List Ciphers by TLD
```sql
SELECT
  t.name,
  dn.name_value,
  c.cipher_name,
  c.sslversion
FROM
  domain_names dn
JOIN domain_ciphers dc ON dn.id = dc.domain_id
JOIN ciphers c ON dc.cipher_id = c.cipher_id
JOIN tlds t on dn.tld_id = t.id
WHERE t.name = ?;
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This provider is licensed under the [LICENSE](LICENSE) file.
