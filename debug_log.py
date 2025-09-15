#!/usr/bin/env python3
"""
Debug script to examine log file structure
"""

import sys


def examine_log_file(file_path, num_lines=10):
    """Examine the structure of the log file"""
    print(f"Examining first {num_lines} lines of: {file_path}")
    print("=" * 60)

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for i, line in enumerate(f):
                if i >= num_lines:
                    break

                line = line.strip()
                print(f"Line {i + 1}:")
                print(f"  Length: {len(line)} characters")
                print(f"  Tabs found: {line.count(chr(9))}")
                print(f"  Starts with: {line[:50]}...")

                # Check if it's likely JSON
                if line.startswith('{') and line.endswith('}'):
                    print("  Format: Likely JSON")
                elif chr(9) in line:  # Tab character
                    print("  Format: Tab-separated")
                    parts = line.split(chr(9))
                    print(f"  Parts: {len(parts)}")
                    for j, part in enumerate(parts[:3]):  # Show first 3 parts
                        print(f"    Part {j + 1}: {part[:30]}...")
                else:
                    print("  Format: Unknown")

                print("-" * 40)

    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python debug_log.py <log_file>")
        sys.exit(1)

    examine_log_file(sys.argv[1])