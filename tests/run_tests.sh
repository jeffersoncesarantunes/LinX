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

echo "--- Test 4: Unknown option error ---"
./linx --bogus > /tmp/lintest_unknown.txt 2>&1; rc=$?
if [ $rc -ne 0 ] && grep -q "Unknown" /tmp/lintest_unknown.txt; then
    echo "  PASS"
    PASS=$((PASS + 1))
else
    echo "  FAIL"
    FAIL=$((FAIL + 1))
fi

echo "--- Test 5: LinSpec parsing ---"
./linx -l tests/sample_linspec.json > /tmp/lintest_linspec.txt 2>&1
if grep -q "loaded" /tmp/lintest_linspec.txt; then
    echo "  PASS"
    PASS=$((PASS + 1))
else
    echo "  FAIL"
    FAIL=$((FAIL + 1))
fi

echo "--- Test 6: K-Scanner parsing ---"
./linx -k tests/sample_kscanner.json > /tmp/lintest_kscan.txt 2>&1
if grep -q "loaded" /tmp/lintest_kscan.txt; then
    echo "  PASS"
    PASS=$((PASS + 1))
else
    echo "  FAIL"
    FAIL=$((FAIL + 1))
fi

echo "--- Test 7: Full correlation ---"
./linx -l tests/sample_linspec.json -k tests/sample_kscanner.json > /tmp/lintest_full.txt 2>&1
if grep -q "Findings" /tmp/lintest_full.txt; then
    echo "  PASS"
    PASS=$((PASS + 1))
else
    echo "  FAIL"
    FAIL=$((FAIL + 1))
fi

echo "--- Test 8: JSON export ---"
./linx -l tests/sample_linspec.json -k tests/sample_kscanner.json -j -o /tmp > /tmp/lintest_json.txt 2>&1
if [ -f /tmp/correlation_report.json ] && grep -q "findings" /tmp/correlation_report.json; then
    echo "  PASS"
    PASS=$((PASS + 1))
else
    echo "  FAIL"
    FAIL=$((FAIL + 1))
fi

rm -f /tmp/lintest_*.txt /tmp/correlation_report.json

echo ""
echo "Results: $PASS passed, $FAIL failed"
exit $FAIL
