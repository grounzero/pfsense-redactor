#!/bin/bash
# Convenience script to run pfSense redactor tests

set -e

# Colours for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Colour

echo -e "${GREEN}pfSense Redactor Test Suite${NC}"
echo "================================"
echo ""

# Check if pytest is installed
if ! command -v pytest &> /dev/null; then
    echo -e "${RED}Error: pytest is not installed${NC}"
    echo "Install with: pip install -r tests/requirements.txt"
    exit 1
fi

# Parse arguments
MODE="all"
VERBOSE=""
PARALLEL=""
UPDATE_REFERENCE=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --fast)
            MODE="fast"
            shift
            ;;
        --slow)
            MODE="slow"
            shift
            ;;
        --reference)
            MODE="reference"
            shift
            ;;
        -v|--verbose)
            VERBOSE="-v"
            shift
            ;;
        -vv)
            VERBOSE="-vv"
            shift
            ;;
        -n|--parallel)
            PARALLEL="-n auto"
            shift
            ;;
        --update-reference)
            UPDATE_REFERENCE="1"
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --fast           Run only fast tests (skip reference snapshots)"
            echo "  --slow           Run only slow tests (reference snapshots)"
            echo "  --reference      Run only reference snapshot tests"
            echo "  -v, --verbose    Verbose output"
            echo "  -vv              Very verbose output"
            echo "  -n, --parallel   Run tests in parallel (requires pytest-xdist)"
            echo "  --update-reference  Update reference files"
            echo "  -h, --help       Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0                    # Run all tests"
            echo "  $0 --fast             # Run only fast tests"
            echo "  $0 --parallel -v      # Run in parallel with verbose output"
            echo "  $0 --update-reference    # Regenerate reference files"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Build pytest command
PYTEST_CMD="pytest tests/"

case $MODE in
    fast)
        echo -e "${YELLOW}Running fast tests only (skipping reference snapshots)${NC}"
        PYTEST_CMD="$PYTEST_CMD -m 'not slow'"
        ;;
    slow)
        echo -e "${YELLOW}Running slow tests only (reference snapshots)${NC}"
        PYTEST_CMD="$PYTEST_CMD -m slow"
        ;;
    reference)
        echo -e "${YELLOW}Running reference snapshot tests${NC}"
        PYTEST_CMD="pytest tests/test_reference_snapshots.py"
        ;;
    all)
        echo -e "${YELLOW}Running all tests${NC}"
        ;;
esac

# Add verbose flag
if [ -n "$VERBOSE" ]; then
    PYTEST_CMD="$PYTEST_CMD $VERBOSE"
fi

# Add parallel flag
if [ -n "$PARALLEL" ]; then
    if ! command -v pytest-xdist &> /dev/null; then
        echo -e "${YELLOW}Warning: pytest-xdist not installed, running sequentially${NC}"
        echo "Install with: pip install pytest-xdist"
    else
        PYTEST_CMD="$PYTEST_CMD $PARALLEL"
    fi
fi

# Set UPDATE_REFERENCE environment variable if requested
if [ -n "$UPDATE_REFERENCE" ]; then
    echo -e "${YELLOW}Updating reference files${NC}"
    export UPDATE_REFERENCE=1
fi

echo ""
echo "Command: $PYTEST_CMD"
echo ""

# Run tests
eval $PYTEST_CMD
EXIT_CODE=$?

echo ""
if [ $EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}✓ All tests passed${NC}"
else
    echo -e "${RED}✗ Some tests failed${NC}"
fi

exit $EXIT_CODE