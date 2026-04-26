#!/bin/bash

echo "CAPSLock EAPE Test Suite"
echo "========================="
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Run all tests
echo "Running all tests..."
echo ""

# Test compliance package
echo "Testing CIS Validator..."
go test -v ./pkg/compliance/cis/... -count=1

if [ $? -eq 0 ]; then
    echo -e "${GREEN}CIS Validator tests PASSED${NC}"
else
    echo -e "${RED}CIS Validator tests FAILED${NC}"
    exit 1
fi

echo ""
echo "Testing PCI-DSS Validator..."
go test -v ./pkg/compliance/pcidss/... -count=1

if [ $? -eq 0 ]; then
    echo -e "${GREEN}PCI-DSS Validator tests PASSED${NC}"
else
    echo -e "${RED}PCI-DSS Validator tests FAILED${NC}"
    exit 1
fi

echo ""
echo "Testing all packages with coverage..."
go test ./pkg/... -coverprofile=coverage.out -count=1

if [ $? -eq 0 ]; then
    echo -e "${GREEN}All tests PASSED${NC}"
else
    echo -e "${RED}Some tests FAILED${NC}"
    exit 1
fi

echo ""
echo "Generating coverage report..."
go tool cover -html=coverage.out -o coverage.html

echo ""
echo -e "${GREEN}Test suite complete!${NC}"
echo "Coverage report: coverage.html"