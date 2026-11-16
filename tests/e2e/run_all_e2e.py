#!/usr/bin/env python3
"""
Hybrid Smart Tunnel - E2E Master Test Runner
Executes E2E test suites across Tiers 1-4 with colorized reporting,
tier filtering, keyword filtering, and structured JSON output.

Zero external dependencies: 100% Python 3.14 standard library.
"""

import os
import sys
import time
import json
import argparse
import unittest
from pathlib import Path
from typing import List, Dict, Any, Optional, Set


# ANSI Color Codes
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


class E2ETestResult(unittest.TextTestResult):
    """Custom TestResult capturing per-test timing, structured status, and ANSI formatting."""

    def __init__(self, stream, descriptions, verbosity, no_color=False):
        super().__init__(stream, descriptions, verbosity)
        self.verbosity = verbosity
        self.showAll = False
        self.dots = False
        self.no_color = no_color or (not stream.isatty() if hasattr(stream, "isatty") else no_color)
        self.results_catalog: List[Dict[str, Any]] = []
        self._test_start_time: float = 0.0

    def _c(self, color: str, text: str) -> str:
        return text if self.no_color else f"{color}{text}{RESET}"

    def startTest(self, test):
        super().startTest(test)
        self._test_start_time = time.time()
        if self.verbosity > 1:
            test_id = test.id().split(".")[-1]
            suite_name = test.__class__.__name__
            self.stream.write(f"  [{suite_name}] {test_id:<42} ... ")
            self.stream.flush()

    def addSuccess(self, test):
        super().addSuccess(test)
        duration = time.time() - self._test_start_time
        self.results_catalog.append({
            "id": test.id(),
            "name": test._testMethodName,
            "suite": test.__class__.__name__,
            "status": "PASS",
            "duration_ms": round(duration * 1000, 2),
            "error": None
        })
        if self.verbosity > 1:
            self.stream.writeln(f"{self._c(GREEN, '✓ PASS')} ({round(duration * 1000, 1)}ms)")
        else:
            self.stream.write(self._c(GREEN, "."))
            self.stream.flush()

    def addFailure(self, test, err):
        super().addFailure(test, err)
        duration = time.time() - self._test_start_time
        err_msg = self._exc_info_to_string(err, test)
        self.results_catalog.append({
            "id": test.id(),
            "name": test._testMethodName,
            "suite": test.__class__.__name__,
            "status": "FAIL",
            "duration_ms": round(duration * 1000, 2),
            "error": err_msg
        })
        if self.verbosity > 1:
            self.stream.writeln(f"{self._c(RED, '✗ FAIL')} ({round(duration * 1000, 1)}ms)")
        else:
            self.stream.write(self._c(RED, "F"))
            self.stream.flush()

    def addError(self, test, err):
        super().addError(test, err)
        duration = time.time() - self._test_start_time
        err_msg = self._exc_info_to_string(err, test)
        self.results_catalog.append({
            "id": test.id(),
            "name": test._testMethodName,
            "suite": test.__class__.__name__,
            "status": "ERROR",
            "duration_ms": round(duration * 1000, 2),
            "error": err_msg
        })
        if self.verbosity > 1:
            self.stream.writeln(f"{self._c(YELLOW, '⚠ ERROR')} ({round(duration * 1000, 1)}ms)")
        else:
            self.stream.write(self._c(YELLOW, "E"))
            self.stream.flush()

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self.results_catalog.append({
            "id": test.id(),
            "name": test._testMethodName,
            "suite": test.__class__.__name__,
            "status": "SKIP",
            "duration_ms": 0.0,
            "error": reason
        })
        if self.verbosity > 1:
            self.stream.writeln(f"{self._c(CYAN, '○ SKIP')} ({reason})")
        else:
            self.stream.write(self._c(CYAN, "S"))
            self.stream.flush()


def parse_tier_args(tier_args: Optional[List[str]]) -> List[int]:
    """Parses tier arguments supporting comma-separated and space-separated formats."""
    if not tier_args:
        return [1, 2, 3, 4]
    parsed_tiers: Set[int] = set()
    for item in tier_args:
        for part in str(item).split(","):
            part = part.strip()
            if part.isdigit():
                val = int(part)
                if 1 <= val <= 4:
                    parsed_tiers.add(val)
    return sorted(parsed_tiers) if parsed_tiers else [1, 2, 3, 4]


def flatten_test_suite(suite: unittest.TestSuite) -> List[unittest.TestCase]:
    """Recursively flattens nested TestSuites into a single list of TestCase objects."""
    tests: List[unittest.TestCase] = []
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            tests.extend(flatten_test_suite(item))
        elif isinstance(item, unittest.TestCase):
            tests.append(item)
    return tests


def discover_tier_suites(tiers: List[int], test_dir: Path, pattern_filter: Optional[str] = None) -> unittest.TestSuite:
    """Discovers test suites mapped to the requested tiers with optional keyword filtering."""
    loader = unittest.TestLoader()
    combined_suite = unittest.TestSuite()

    tier_file_mapping = {
        1: ("test_tier1_features.py", "Tier 1: Feature Coverage"),
        2: ("test_tier2_boundaries.py", "Tier 2: Boundary & Corner Cases"),
        3: ("test_tier3_combinations.py", "Tier 3: Cross-Feature Combinations"),
        4: ("test_tier4_workloads.py", "Tier 4: Real-World Workloads")
    }

    for t in sorted(tiers):
        filename, desc = tier_file_mapping.get(t, (None, None))
        if not filename:
            continue
        filepath = test_dir / filename
        if not filepath.exists():
            continue

        try:
            discovered = loader.discover(
                start_dir=str(test_dir),
                pattern=filename,
                top_level_dir=str(test_dir.parent.parent)
            )
            all_tests = flatten_test_suite(discovered)
            for test in all_tests:
                if pattern_filter:
                    test_full_id = test.id().lower()
                    if pattern_filter.lower() in test_full_id:
                        combined_suite.addTest(test)
                else:
                    combined_suite.addTest(test)
        except Exception as e:
            print(f"Warning: Failed to discover tests in {filename}: {e}", file=sys.stderr)

    return combined_suite


def build_parser() -> argparse.ArgumentParser:
    """Constructs the command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="smart-tunnel-e2e",
        description="Hybrid Smart Tunnel - Master E2E Test Suite Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 tests/e2e/run_all_e2e.py                    # Run all tiers (1-4)
  python3 tests/e2e/run_all_e2e.py --tier 3,4         # Run Tier 3 and Tier 4 only
  python3 tests/e2e/run_all_e2e.py --tier 3 -v        # Run Tier 3 verbose
  python3 tests/e2e/run_all_e2e.py -k M1-F04          # Run tests matching M1-F04
  python3 tests/e2e/run_all_e2e.py --json report.json # Save JSON report
  python3 tests/e2e/run_all_e2e.py --fail-fast        # Stop on first failure
"""
    )
    parser.add_argument(
        "--tier", "-t",
        nargs="+",
        metavar="TIER",
        default=["1", "2", "3", "4"],
        help="Test tiers to execute (e.g. 1, 2, 3, 4 or '3,4'). Default: 1, 2, 3, 4"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="count",
        default=1,
        help="Increase output verbosity (-v or -vv)"
    )
    parser.add_argument(
        "--json",
        nargs="?",
        const="stdout",
        metavar="FILE",
        help="Export machine-readable JSON results to FILE (or stdout if omitted)"
    )
    parser.add_argument(
        "-k", "--keyword",
        dest="keyword",
        metavar="PATTERN",
        help="Filter test cases by keyword, test ID, or feature ID (case-insensitive)"
    )
    parser.add_argument(
        "--fail-fast",
        action="store_true",
        help="Abort test execution on the first failure or error"
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color output"
    )
    return parser


def print_banner(tiers: List[int], total_tests: int, no_color: bool = False):
    """Prints a styled execution banner."""
    c_bold = "" if no_color else BOLD
    c_cyan = "" if no_color else CYAN
    c_reset = "" if no_color else RESET
    print(f"\n{c_bold}{c_cyan}╔════════════════════════════════════════════════════════════════════╗{c_reset}")
    print(f"{c_bold}{c_cyan}║             Hybrid Smart Tunnel — Master E2E Test Runner            ║{c_reset}")
    print(f"{c_bold}{c_cyan}╚════════════════════════════════════════════════════════════════════╝{c_reset}")
    tier_str = ", ".join(f"Tier {t}" for t in tiers)
    print(f"  Target Tiers      : {tier_str}")
    print(f"  Discovered Tests  : {total_tests}")
    print(f"  Timestamp         : {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}\n")


def print_summary_table(result: E2ETestResult, elapsed: float, no_color: bool = False):
    """Prints a structured summary table of the test results."""
    c_bold = "" if no_color else BOLD
    c_green = "" if no_color else GREEN
    c_red = "" if no_color else RED
    c_yellow = "" if no_color else YELLOW
    c_cyan = "" if no_color else CYAN
    c_reset = "" if no_color else RESET

    passed = result.testsRun - len(result.failures) - len(result.errors) - len(result.skipped)
    failed = len(result.failures)
    errors = len(result.errors)
    skipped = len(result.skipped)

    print(f"\n{c_bold}═══════════════════════════════════ Test Summary ═══════════════════════════════════{c_reset}")
    print(f"  Total Executed    : {result.testsRun}")
    print(f"  Passed            : {c_green}{passed}{c_reset}")
    print(f"  Failed            : {c_red if failed else ''}{failed}{c_reset}")
    print(f"  Errors            : {c_yellow if errors else ''}{errors}{c_reset}")
    print(f"  Skipped           : {c_cyan if skipped else ''}{skipped}{c_reset}")
    print(f"  Total Duration    : {round(elapsed, 3)}s")
    print(f"{c_bold}════════════════════════════════════════════════════════════════════════════════════{c_reset}")

    if result.wasSuccessful():
        print(f"  Result: {c_bold}{c_green}OVERALL SUCCESS — ALL TESTS PASSED{c_reset}\n")
    else:
        print(f"  Result: {c_bold}{c_red}TEST SUITE FAILED ({failed} failures, {errors} errors){c_reset}\n")


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    active_tiers = parse_tier_args(args.tier)
    test_dir = Path(__file__).resolve().parent

    # Add paths for import resolution
    if str(test_dir) not in sys.path:
        sys.path.insert(0, str(test_dir))
    repo_root = str(test_dir.parent.parent)
    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)

    suite = discover_tier_suites(active_tiers, test_dir, args.keyword)
    total_discovered = suite.countTestCases()

    if not args.json or args.json != "stdout":
        print_banner(active_tiers, total_discovered, args.no_color)

    if total_discovered == 0:
        if not args.json or args.json != "stdout":
            print("No matching tests discovered.")
        return 0

    start_time = time.time()
    stream_output = sys.stderr if (args.json == "stdout") else sys.stdout

    runner = unittest.TextTestRunner(
        stream=stream_output,
        resultclass=lambda s, d, v: E2ETestResult(s, d, v, no_color=args.no_color),
        verbosity=args.verbose,
        failfast=args.fail_fast
    )

    test_result: E2ETestResult = runner.run(suite)  # type: ignore
    elapsed = time.time() - start_time

    if not args.json or args.json != "stdout":
        print_summary_table(test_result, elapsed, args.no_color)

    # Compile structured JSON report
    passed_count = test_result.testsRun - len(test_result.failures) - len(test_result.errors) - len(test_result.skipped)
    catalog = getattr(test_result, "results_catalog", [])

    # Group by tier
    tier_counts = {1: {"total": 0, "passed": 0, "failed": 0},
                   2: {"total": 0, "passed": 0, "failed": 0},
                   3: {"total": 0, "passed": 0, "failed": 0},
                   4: {"total": 0, "passed": 0, "failed": 0}}

    for entry in catalog:
        suite_name = entry.get("suite", "")
        t_num = 0
        if "Tier1" in suite_name or "tier1" in suite_name.lower():
            t_num = 1
        elif "Tier2" in suite_name or "tier2" in suite_name.lower():
            t_num = 2
        elif "Tier3" in suite_name or "tier3" in suite_name.lower():
            t_num = 3
        elif "Tier4" in suite_name or "tier4" in suite_name.lower():
            t_num = 4

        if t_num in tier_counts:
            tier_counts[t_num]["total"] += 1
            if entry.get("status") == "PASS":
                tier_counts[t_num]["passed"] += 1
            elif entry.get("status") in ("FAIL", "ERROR"):
                tier_counts[t_num]["failed"] += 1

    json_report = {
        "version": "1.0",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "summary": {
            "total": test_result.testsRun,
            "passed": passed_count,
            "failed": len(test_result.failures),
            "errors": len(test_result.errors),
            "skipped": len(test_result.skipped),
            "duration_seconds": round(elapsed, 3),
            "success": test_result.wasSuccessful(),
            "exit_code": 0 if test_result.wasSuccessful() else 1
        },
        "tiers": tier_counts,
        "results": catalog
    }

    if args.json:
        if args.json == "stdout":
            print(json.dumps(json_report, indent=2))
        else:
            out_path = Path(args.json)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(json_report, f, indent=2)
            if not args.json == "stdout":
                print(f"Structured JSON report saved to: {out_path.resolve()}")

    return 0 if test_result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
