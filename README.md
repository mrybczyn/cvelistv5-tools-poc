# Proof of concept CVEv5 usage for CVE checking

This is a proof-of-concept tooling for checking for CVEs in a given
product using the CVEv5 database (JSON format).

## Usage

Example use:

python check_one_cvev5.py -i cves/ -p curl -r 7.59.0

We check using the database in the local directory cves/
for product "curl" in version 7.59.0

## Data sources

This tool uses data as formatted in https://github.com/CVEProject/cvelistV5
or a copy of this repository with fixes of malformed entries.

Tested with:
https://github.com/mrybczyn/cvelistV5-overrides

You are welcome to submit pull requests to the above repository.

## TODO

* The work to integrate it with other tooling for massive checks
