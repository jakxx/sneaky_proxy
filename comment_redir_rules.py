#!/usr/bin/env python3

import ipaddress
import argparse
import shutil
import re

def load_cidrs(file_path):
    cidrs = []
    with open(file_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                cidrs.append(ipaddress.ip_network(line))
            except ValueError:
                print(f"Warning: Invalid CIDR '{line}' in {file_path}, skipping.")
    return cidrs

def load_rules(file_path):
    with open(file_path, "r") as f:
        return f.readlines()

def save_rules(file_path, lines):
    with open(file_path, "w") as f:
        f.writelines(lines)

def extract_cidr_from_rule(line):
    match = re.search(r"-R\s+'([\d./]+)'", line)
    if match:
        try:
            return ipaddress.ip_network(match.group(1))
        except ValueError:
            return None
    return None

def find_matching_lines(rules, target_cidrs):
    matches = []
    for i, line in enumerate(rules):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        rule_cidr = extract_cidr_from_rule(stripped)
        if not rule_cidr:
            continue
        for target in target_cidrs:
            if target.subnet_of(rule_cidr) or target.overlaps(rule_cidr):
                matches.append((i, line))
                break
    return matches

def main():
    parser = argparse.ArgumentParser(description="Comment out redirect rules matching target CIDRs")
    parser.add_argument("rules_file", help="Path to redirect.rules")
    parser.add_argument("cidr_file", help="Path to file containing target CIDRs")
    args = parser.parse_args()

    rules_file = args.rules_file
    cidr_file = args.cidr_file

    backup_file = rules_file + ".bak"
    shutil.copyfile(rules_file, backup_file)
    print(f"Backup of original file saved as {backup_file}")

    target_cidrs = load_cidrs(cidr_file)
    rules = load_rules(rules_file)

    matches = find_matching_lines(rules, target_cidrs)

    if not matches:
        print("No matching lines found.")
        return

    print("Matching lines found:")
    for idx, line in matches:
        print(f"{idx+1}: {line.strip()}")

    for idx, line in matches:
        prompt = f"Comment out line {idx+1}: '{line.strip()}'? (y/n): "
        choice = input(prompt).strip().lower()
        if choice == 'y':
            rules[idx] = "#" + line if not line.startswith("#") else line

    save_rules(rules_file, rules)
    print(f"Finished. Updated rules saved to {rules_file}")

if __name__ == "__main__":
    main()