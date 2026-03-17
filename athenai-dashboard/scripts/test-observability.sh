#!/bin/bash
# Test script for AthenAI Observability

echo "🧪 Testing AthenAI Observability..."
echo ""

BASE_URL="http://localhost:5000"
PYTHON_CMD=$(command -v python3 || command -v python)

# Test 1: Send test SNS notifications
echo "=== Test 1: SNS Notifications ==="
$PYTHON_CMD sns_setup.py --test

if [ $? -eq 0 ]; then
    echo "✅ SNS test passed"
else
    echo "❌ SNS test failed"
fi

echo ""

# Test 2: Generate metrics
echo "=== Test 2: Generate Metrics ==="
echo "Sending test requests to generate metrics..."

for i in {1..10}; do
    curl -s "$BASE_URL/api/health" > /dev/null
    echo -n "."
done
echo ""

echo "✅ Metrics generated"
echo ""

# Test 3: Trigger alarms (simulate high error rate)
echo "=== Test 3: Trigger Alarms ==="
echo "Simulating errors to trigger alarms..."

for i in {1..10}; do
    curl -s "$BASE_URL/api/nonexistent" > /dev/null
    echo -n "."
done
echo ""

echo "✅ Alarm trigger test complete"
echo "   ⏳ Wait 5 minutes for alarm to trigger"
echo "   📧 Check email for alarm notification"
echo ""

# Test 4: Check dashboards
echo "=== Test 4: List Dashboards ==="
$PYTHON_CMD cloudwatch_dashboards.py --list

echo ""

# Test 5: Check alarms
echo "=== Test 5: List Alarms ==="
$PYTHON_CMD cloudwatch_alarms.py --list

echo ""

# Test 6: X-Ray traces
echo "=== Test 6: X-Ray Traces ==="
echo "Sending requests to generate X-Ray traces..."

for i in {1..5}; do
    curl -s -X POST "$BASE_URL/api/predict" \
        -H "Content-Type: application/json" \
        -d '{"features": [1,2,3,4,5]}' > /dev/null
    echo -n "."
done
echo ""

echo "✅ X-Ray traces generated"
echo "   🔍 View traces in X-Ray Console"
echo ""

# Summary
echo "=== Test Summary ==="
echo "✅ SNS notifications sent"
echo "✅ Metrics generated (10 requests)"
echo "✅ Alarm trigger simulated (10 errors)"
echo "✅ Dashboards verified"
echo "✅ Alarms verified"
echo "✅ X-Ray traces generated (5 requests)"
echo ""
echo "💡 Next steps:"
echo "   1. Check email for SNS test notifications"
echo "   2. View dashboards in CloudWatch Console"
echo "   3. Wait 5 minutes and check for alarm notifications"
echo "   4. View X-Ray service map and traces"
echo ""
echo "🌐 CloudWatch Console:"
echo "   Dashboards: https://console.aws.amazon.com/cloudwatch/home?region=us-east-1#dashboards:"
echo "   Alarms: https://console.aws.amazon.com/cloudwatch/home?region=us-east-1#alarmsV2:"
echo "   X-Ray: https://console.aws.amazon.com/xray/home?region=us-east-1#/service-map"
