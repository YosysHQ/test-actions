#!/usr/bin/env python3

import argparse
import os
import xml.etree.ElementTree as ET
from pathlib import Path


def get_list_of_files(dir_name):
    all_files = []
    for root, _, files in os.walk(dir_name):
        for name in files:
            full_path = os.path.join(root, name)
            if Path(full_path).suffix == ".result":
                all_files.append(full_path)
    return all_files


def main():
    parser = argparse.ArgumentParser(
        description="Generate a JUnit XML report from .result files."
    )
    parser.add_argument(
        "directory",
        nargs="?",
        default=".",
        help="Directory to scan (default: current directory)",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="report.xml",
        help="Output XML file (default: report.xml)",
    )
    args = parser.parse_args()

    list_of_files = sorted(get_list_of_files(args.directory))

    testsuits = []
    casenumber = {}
    failures = {}

    total_pass = 0
    total_fail = 0

    for elem in list_of_files:
        rel = os.path.relpath(elem, args.directory)
        parts = rel.split(os.sep)
        testsuit = parts[0] if parts else "root"

        if testsuit not in testsuits:
            testsuits.append(testsuit)
            casenumber[testsuit] = 0
            failures[testsuit] = 0

        casenumber[testsuit] += 1

        with open(elem) as f:
            status = f.read().strip()

        if status == "PASS":
            total_pass += 1
        elif status == "FAIL":
            total_fail += 1
            failures[testsuit] += 1

    total_tests = total_pass + total_fail

    root = ET.Element(
        "testsuites",
        {
            "tests": str(total_tests),
            "failures": str(total_fail),
            "errors": "0",
            "time": "0",
        },
    )

    for suite in testsuits:
        suite_xml = ET.SubElement(
            root,
            "testsuite",
            {
                "name": suite,
                "tests": str(casenumber[suite]),
                "failures": str(failures[suite]),
                "errors": "0",
                "skipped": "0",
                "time": "0",
            },
        )

        for elem in list_of_files:
            rel = os.path.relpath(elem, args.directory)
            parts = rel.split(os.sep)
            testsuit = parts[0] if parts else "root"

            if testsuit != suite:
                continue

            testcase = Path(elem).stem

            with open(elem) as f:
                status = f.read().strip()

            case = ET.SubElement(
                suite_xml,
                "testcase",
                {
                    "classname": testsuit,
                    "name": testcase,
                    "time": "0",
                },
            )

            if status == "FAIL":
                failure = ET.SubElement(
                    case,
                    "failure",
                    {
                        "message": "FAIL",
                        "type": "failure",
                    },
                )
                failure.text = "Test failed."

                err_file = Path(elem).with_suffix(".err")
                if err_file.is_file():
                    system_err = ET.SubElement(case, "system-err")
                    with open(err_file) as logf:
                        system_err.text = logf.read()

        ET.SubElement(suite_xml, "system-out")
        ET.SubElement(suite_xml, "system-err")

    ET.indent(root, space="  ")

    tree = ET.ElementTree(root)
    tree.write(
        args.output,
        encoding="utf-8",
        xml_declaration=True,
    )


if __name__ == "__main__":
    main()
