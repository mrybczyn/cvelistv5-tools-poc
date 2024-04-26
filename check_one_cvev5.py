# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: Copyright 2024 Marta Rybczynska

import json
import os
import re
import argparse
from cvev5 import get_status, parse_cve_id

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="CVE lookup in CVEV5 database for a given product"
    )
    parser.add_argument("-i", "--input-dir", help="Input directory", required=True)
    parser.add_argument("-p", "--product", help="Product name", required=True)
    parser.add_argument("-e", "--vendor", help="Vendor name", default=None)
    parser.add_argument("-r", "--version", help="Product version", required=True)
    args = parser.parse_args()

    input_dir = args.input_dir
    product = args.product.lower()
    if args.vendor is not None:
        vendor = args.vendor.lower()
    else:
        vendor = "*"
    version = args.version

    products = []

    print("Loading database...")
    for root, dirnames, filenames in os.walk(input_dir):
        for filename in filenames:
            year, number = parse_cve_id(filename)
            if filename.endswith((".json")) and year is not None:
                with open(os.path.join(root, filename)) as f:
                    data = json.load(f)
                    try:
                        if "containers" in data:
                            if "cna" in data["containers"]:
                                if "affected" in data["containers"]["cna"]:
                                    # print (data['containers']['cna']['affected'][0])
                                    for x in data["containers"]["cna"]["affected"]:
                                        products.append(
                                            (x["product"].lower(), x, data, filename)
                                        )

                    except KeyError:
                        pass
                    except TypeError:
                        pass
    print("Database loaded")
    products_sorted = sorted(products, key=lambda product: product[0])
    print("Product count: " + str(len(products)))

    get_status(products_sorted, product, vendor, version)
