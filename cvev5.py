# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: Copyright 2024 Marta Rybczynska

import json
import os
import re


def parse_cve_id(cve):
    pattern = pattern = r"CVE-(\d{4})-(\d+)\.json"
    match = re.match(pattern, cve)
    if match:
        year = match.group(1)
        number = match.group(2)
        return year, number
    else:
        return None, None


def is_semver(version):
    if version == "unspecified":
        return True
    if version == "0":
        return True

    version_parts = version.split(".")
    if len(version_parts) == 3:
        return True
    return False


def match_semver(version, target_version):
    # Special case, 0 means "first available"
    if version == "0":
        return True

    version_parts = version.split(".")
    target_parts = target_version.split(".")

    # Compare major and minor versions
    if version_parts[0] == target_parts[0] and version_parts[1] == target_parts[1]:
        return True
    else:
        return False


def match_semver_less_equal(version, target_version):
    version_parts = version.split(".")
    target_parts = target_version.split(".")

    # Compare major and minor versions
    if version_parts[0] >= target_parts[0]:
        return True

    if version_parts[1] >= target_parts[1]:
        return True

    if version_parts[2] >= target_parts[2]:
        return True

    return False


def match_semver_less(version, target_version):
    version_parts = version.split(".")
    target_parts = target_version.split(".")

    # Compare major and minor versions
    if version_parts[0] > target_parts[0]:
        return True

    if version_parts[1] > target_parts[1]:
        return True

    if version_parts[2] > target_parts[2]:
        return True

    return False


def parse_cpe_entry(cpe_entry):
    parts = cpe_entry.split(":")
    vendor_name = parts[3]
    product_name = parts[4]
    version = parts[5]

    if vendor_name == "*":
        vendor_name = None
    return vendor_name, product_name, version


def is_affected(entries, version):
    if "versions" not in entries:
        if "defaultStatus" in entries:
            if entries["defaultStatus"] == "affected":
                return "affected"
            elif entries["defaultStatus"] == "unaffected":
                return "not affected"
        return "unknown"

    for entry in entries["versions"]:

        # Entries like  'versions': [{'status': 'affected', 'version': '3.5.12'}]}
        if (entry["status"] == "affected") and "versionType" not in entry:
            if entry["version"] == version:
                return "affected"
            # If has only one version, but doesn't match ours, try another entry
            if is_semver(entry["version"]):
                continue
            # Malformed/unsupported type of version
            print("Malformed entry... skipping " + str(entry))
            return "unknown"

        # Malformed/unsupported version, skip parsing
        if (entry["status"] == "affected") and not is_semver(entry["version"]):
            print("Malformed entry... skipping " + str(entry))
            return "unknown"

        if (
            (entry["status"] == "affected")
            and (entry["versionType"] == "semver" or entry["versionType"] == "custom")
            and match_semver(entry["version"], version)
        ):
            if "lessThanOrEqual" in entry:
                if match_semver_less_equal(entry["lessThanOrEqual"], version):
                    return "affected"
            elif "lessThan" in entry:
                if match_semver_less(entry["lessThan"], version):
                    return "affected"

    return "not affected"


def get_status(db, product, vendor, version):
    for pr in db:
        if pr[0].lower() == product and (
            (vendor == "*") or (vendor == pr[1]["vendor"].lower())
        ):
            vuln_status = is_affected(pr[1], version)
            if vuln_status == "affected":
                print(pr[3] + ": affected: " + product + " " + version)
            elif vuln_status == "unknown":
                print(pr[3] + ": unknown status: " + product + " " + version)
            elif vuln_status == "not affected":
                print(pr[3] + ": not affected " + product + " " + version)
