#!/bin/bash
# Setup script for AthenAI Observability

echo "🚀 Setting up AthenAI Observability..."
echo ""

# Check Python
if ! command -v python &> /dev/null && ! command -v python3 &> /dev/null; then
    echo "❌ Python is not installed"
    exit 1
fi

PYTHON_CMD=$(command -v python3 || command -v python)
echo "✅ Python found: $PYTHON_CMD"
echo ""

# Install dependencies
echo "📦 Installing dependencies..."
$PYTHON_CMD -m pip install -q aws-xray-sdk==2.12.0

if [ $? -eq 0 ]; then
    echo "✅ Dependencies installed"
else
    echo "❌ Failed to install dependencies"
    exit 1
fi

echo ""

# Setup SNS Topics
echo "📧 Setting up SNS topics..."
read -p "Enter your email for notifications (or press Enter to skip): " EMAIL

if [ -n "$EMAIL" ]; then
    $PYTHON_CMD sns_setup.py --email "$EMAIL"
else
    $PYTHON_CMD sns_setup.py
fi

echo ""

# Setup CloudWatch Dashboards
echo "📊 Setting up CloudWatch Dashboards..."
$PYTHON_CMD cloudwatch_dashboards.py

if [ $? -eq 0 ]; then
    echo "✅ Dashboards created"
else
    echo "❌ Failed to create dashboards"
fi

echo ""

# Setup CloudWatch Alarms
echo "🚨 Setting up CloudWatch Alarms..."
$PYTHON_CMD cloudwatch_alarms.py

if [ $? -eq 0 ]; then
    echo "✅ Alarms created"
else
    echo "❌ Failed to create alarms"
fi

echo ""
echo "✅ Observability setup complete!"
echo ""
echo "📋 Summary:"
echo "   - SNS Topics: 3 (critical, warning, info)"
echo "   - CloudWatch Dashboards: 3 (security, ML, performance)"
echo "   - CloudWatch Alarms: 12 (5 critical, 5 warning, 2 info)"
echo "   - AWS X-Ray: Middleware ready"
echo ""
echo "💡 Next steps:"
echo "   1. Check your email and confirm SNS subscriptions"
echo "   2. Restart Flask app to enable X-Ray tracing"
echo "   3. View dashboards in CloudWatch Console"
echo "   4. Test alarms with: ./scripts/test-observability.sh"
echo ""
echo "🌐 Access:"
if [ -n "$AWS_ENDPOINT_URL" ]; then
    echo "   LocalStack: $AWS_ENDPOINT_URL"
else
    echo "   LocalStack: http://localhost:4566"
fi
echo "   CloudWatch Console: https://console.aws.amazon.com/cloudwatch"
