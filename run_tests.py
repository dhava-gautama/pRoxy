#!/usr/bin/env python3
"""
pRoxy Test Runner

Convenient script to run different types of tests with proper environment setup.
"""
import os
import sys
import subprocess
import argparse
from pathlib import Path


def setup_test_environment():
    """Set up the test environment."""
    os.environ["PROXY_DISABLE_AUTH"] = "true"
    os.environ["TESTING"] = "true"

    # Add project root to Python path
    project_root = Path(__file__).parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

    # Also set PYTHONPATH environment variable for subprocess
    current_pythonpath = os.environ.get("PYTHONPATH", "")
    if current_pythonpath:
        os.environ["PYTHONPATH"] = f"{project_root}:{current_pythonpath}"
    else:
        os.environ["PYTHONPATH"] = str(project_root)


def run_command(cmd, description):
    """Run a command and handle output."""
    print(f"\n{'='*60}")
    print(f"🧪 {description}")
    print(f"{'='*60}")
    print(f"Command: {' '.join(cmd)}\n")

    try:
        result = subprocess.run(cmd, check=True, capture_output=False)
        print(f"\n✅ {description} - PASSED")
        return True
    except subprocess.CalledProcessError as e:
        print(f"\n❌ {description} - FAILED (exit code: {e.returncode})")
        return False


def main():
    parser = argparse.ArgumentParser(description="pRoxy Test Runner")
    parser.add_argument(
        "--type",
        choices=["all", "api", "security", "rules", "proxy", "fast"],
        default="all",
        help="Type of tests to run"
    )
    parser.add_argument(
        "--coverage",
        action="store_true",
        help="Run with coverage report"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output"
    )
    parser.add_argument(
        "--parallel", "-n",
        type=int,
        help="Number of parallel workers (requires pytest-xdist)"
    )
    parser.add_argument(
        "--markers", "-m",
        type=str,
        help="Run only tests matching marker expression"
    )

    args = parser.parse_args()

    # Setup environment
    setup_test_environment()

    # Check if virtual environment is activated
    if not os.environ.get("VIRTUAL_ENV") and not sys.prefix != sys.base_prefix:
        print("⚠️  Warning: No virtual environment detected")
        print("   Run: source .venv/bin/activate")
        print()

    # Build pytest command
    cmd = ["python", "-m", "pytest"]

    # Add verbosity
    if args.verbose:
        cmd.extend(["-v", "-s"])

    # Add parallel execution
    if args.parallel:
        cmd.extend(["-n", str(args.parallel)])

    # Add test selection
    if args.type == "fast":
        cmd.extend(["-m", "not slow"])
    elif args.type != "all":
        if args.type == "api":
            cmd.extend(["tests/api/"])
        elif args.type == "security":
            cmd.extend(["tests/security/"])
        elif args.type == "rules":
            cmd.extend(["tests/rules/"])
        elif args.type == "proxy":
            cmd.extend(["tests/proxy/"])

    # Add custom markers
    if args.markers:
        cmd.extend(["-m", args.markers])

    # Add coverage if requested
    if args.coverage:
        cmd.extend([
            "--cov=api",
            "--cov=state",
            "--cov=pRoxy",
            "--cov-report=term-missing",
            "--cov-report=html:htmlcov"
        ])

    # Run the tests
    print("🚀 Starting pRoxy Test Suite")
    print(f"Test type: {args.type}")
    if args.coverage:
        print("Coverage: enabled")
    if args.parallel:
        print(f"Parallel workers: {args.parallel}")
    print()

    success = run_command(cmd, f"Running {args.type} tests")

    if success:
        print(f"\n🎉 All tests passed!")
        if args.coverage:
            print(f"📊 Coverage report: htmlcov/index.html")
    else:
        print(f"\n💥 Some tests failed!")
        sys.exit(1)


if __name__ == "__main__":
    main()