"""Run all unit tests with coverage reporting."""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pytest
import subprocess


def run_tests(coverage=True, verbose=False):
    """Run all tests with optional coverage.

    Args:
        coverage: Whether to generate coverage report
        verbose: Whether to run pytest in verbose mode

    Returns:
        Exit code from pytest
    """
    args = [
        'pytest',
        'tests/',
        '-v' if verbose else '',
        '--tb=short',
        '--strict-markers',
    ]

    if coverage:
        args.extend([
            '--cov=wa1kpcap',
            '--cov-report=html:htmlcov',
            '--cov-report=term-missing',
            '--cov-fail-under=80',
        ])

    # Filter empty strings
    args = [a for a in args if a]

    print(f"Running: {' '.join(args)}")

    result = pytest.main(args[1:])
    return result


def run_specific_test(test_file, coverage=False, verbose=False):
    """Run a specific test file.

    Args:
        test_file: Path to test file (e.g., 'tests/test_flow.py')
        coverage: Whether to generate coverage report
        verbose: Whether to run pytest in verbose mode
    """
    args = [
        'pytest',
        test_file,
        '-v' if verbose else '',
        '--tb=short',
    ]

    if coverage:
        args.extend([
            '--cov=wa1kpcap',
            '--cov-report=term-missing',
        ])

    args = [a for a in args if a]

    return pytest.main(args[1:])


def run_test_module(module_name, coverage=False, verbose=False):
    """Run tests for a specific module.

    Args:
        module_name: Name of the test module (e.g., 'test_flow')
        coverage: Whether to generate coverage report
        verbose: Whether to run pytest in verbose mode
    """
    test_file = f'tests/{module_name}.py'
    return run_specific_test(test_file, coverage, verbose)


def list_tests():
    """List all available test files."""
    test_dir = 'tests'
    if os.path.exists(test_dir):
        for f in sorted(os.listdir(test_dir)):
            if f.startswith('test_') and f.endswith('.py'):
                print(f"  {f}")


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Run wa1kpcap unit tests')
    parser.add_argument('--no-coverage', action='store_true', help='Disable coverage reporting')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-t', '--test', type=str, help='Run specific test file')
    parser.add_argument('-m', '--module', type=str, help='Run specific test module')
    parser.add_argument('-l', '--list', action='store_true', help='List available tests')

    args = parser.parse_args()

    if args.list:
        print("Available test files:")
        list_tests()
        sys.exit(0)

    coverage = not args.no_coverage

    if args.test:
        sys.exit(run_specific_test(args.test, coverage, args.verbose))
    elif args.module:
        sys.exit(run_test_module(args.module, coverage, args.verbose))
    else:
        sys.exit(run_tests(coverage, args.verbose))
