#!/bin/bash

PASS=0
FAIL=0

echo "LinX Test Suite"
echo "========================="
echo ""

echo "--- Test 1: Help output ---"
./linx --help > /tmp/lintest_help.txt 2>&1
if grep -q "Usage:" /tmp/lintest_help.txt; then
    echo "  PASS"
    PASS=$((PASS + 1))
else
    echo "  FAIL"
    FAIL=$((FAIL + 1))
fi

echo "--- Test 2: Version output ---"
./linx -V > /tmp/lintest_version.txt 2>&1
if grep -q "LinX" /tmp/lintest_version.txt; then
    echo "  PASS"
    PASS=$((PASS + 1))
else
    echo "  FAIL"
    FAIL=$((FAIL + 1))
fi

echo "--- Test 3: Missing input error ---"
./linx > /tmp/lintest_noinput.txt 2>&1; rc=$?
if [ $rc -ne 0 ] && grep -q "required" /tmp/lintest_noinput.txt; then
    echo "  PASS"
    PASS=$((PASS + 1))
else
    echo "  FAIL"
    FAIL=$((FAIL + 1))
fi

rm -f /tmp/lintest_*.txt

echo ""
echo "Results: $PASS passed, $FAIL failed"
exit $FAIL
