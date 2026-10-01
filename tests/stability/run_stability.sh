#!/usr/bin/env bash
#
# Quantaureum 7-Day Stability Test Runner
#
# Usage:
#   ./run_stability.sh              # CI mode: 10 minutes
#   ./run_stability.sh 30m          # Custom duration: 30 minutes
#   ./run_stability.sh 168h         # Full 7-day production run
#   ./run_stability.sh 1h 500       # 1 hour with 500x acceleration
#
# Environment variables:
#   STABILITY_DURATION       Test duration (default: 10m for CI)
#   STABILITY_ACCELERATION   Time acceleration factor (default: 100)
#   STABILITY_MEMORY_LIMIT   Max heap growth in MB (default: 4096)
#   STABILITY_GOROUTINE_LIMIT Max goroutine count (default: 500)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Parse command line arguments
DURATION="${1:-}"
ACCELERATION="${2:-}"

# Set defaults
if [ -z "$DURATION" ]; then
    DURATION="${STABILITY_DURATION:-10m}"
fi
if [ -z "$ACCELERATION" ]; then
    ACCELERATION="${STABILITY_ACCELERATION:-100}"
fi

# Calculate timeout (duration + 5 minutes buffer)
# Parse duration into seconds for timeout calculation
DURATION_SECONDS=$(echo "$DURATION" | sed 's/h/*3600/' | sed 's/m/*60/' | sed 's/s//' | bc 2>/dev/null || echo "600")
TIMEOUT_SECONDS=$((DURATION_SECONDS + 300))

echo "============================================"
echo "  Quantaureum 7-Day Stability Test"
echo "============================================"
echo ""
echo "  Duration:     $DURATION"
echo "  Acceleration: ${ACCELERATION}x"
echo "  Simulated:    ~$(echo "$DURATION_SECONDS * $ACCELERATION" | bc | head -c 20) seconds"
echo "  Timeout:      ${TIMEOUT_SECONDS}s"
echo "  Project:      $PROJECT_ROOT"
echo ""
echo "  Started at:   $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo "============================================"
echo ""

# Export environment variables for the test
export STABILITY_DURATION="$DURATION"
export STABILITY_ACCELERATION="$ACCELERATION"

# Create output directory
OUTPUT_DIR="$SCRIPT_DIR/results"
mkdir -p "$OUTPUT_DIR"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_FILE="$OUTPUT_DIR/stability_${TIMESTAMP}.log"

echo "Output will be saved to: $OUTPUT_FILE"
echo ""

# Run the test
cd "$PROJECT_ROOT"

echo "Running individual stability tests..."
echo ""

# Run each test separately for better isolation and reporting
FAILED=0
PASSED=0

run_test() {
    local test_name="$1"
    local timeout="$2"
    shift 2

    echo "--- Running $test_name ---"
    if go test -run "$test_name" -v -timeout "${timeout}" \
        -count=1 \
        ./tests/stability/ \
        "$@" 2>&1 | tee -a "$OUTPUT_FILE"; then
        echo "  ✓ $test_name PASSED"
        PASSED=$((PASSED + 1))
    else
        echo "  ✗ $test_name FAILED"
        FAILED=$((FAILED + 1))
    fi
    echo ""
}

# Quick tests (no duration needed)
run_test "TestMemoryStability" "5m"
run_test "TestGoroutineStability" "5m"
run_test "TestConsensusStability" "10m"
run_test "TestStateConsistency" "5m"

# Long-running test
run_test "Test7DayStability" "${TIMEOUT_SECONDS}s"

# Summary
echo ""
echo "============================================"
echo "  Stability Test Summary"
echo "============================================"
echo ""
echo "  Passed: $PASSED"
echo "  Failed: $FAILED"
echo "  Total:  $((PASSED + FAILED))"
echo ""
echo "  Finished at: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo "  Full log:    $OUTPUT_FILE"
echo "============================================"

if [ "$FAILED" -gt 0 ]; then
    echo ""
    echo "⚠️  Some tests failed! Check the log for details."
    exit 1
fi

echo ""
echo "✅ All stability tests passed!"
exit 0
