#!/bin/bash
# WAF Testing Script for AthenAI

echo "🧪 Testing WAF Rules for AthenAI..."
echo ""

BASE_URL="https://localhost"
FAILED=0
PASSED=0

# Function to test attack
test_attack() {
    local name="$1"
    local url="$2"
    local data="$3"
    local expected_status="$4"
    
    echo -n "Testing $name... "
    
    if [ -z "$data" ]; then
        response=$(curl -k -s -o /dev/null -w "%{http_code}" "$BASE_URL$url")
    else
        response=$(curl -k -s -o /dev/null -w "%{http_code}" -X POST -d "$data" "$BASE_URL$url")
    fi
    
    if [ "$response" == "$expected_status" ]; then
        echo "✅ PASSED (HTTP $response)"
        ((PASSED++))
    else
        echo "❌ FAILED (Expected $expected_status, got $response)"
        ((FAILED++))
    fi
}

echo "=== SQL Injection Tests ==="
test_attack "SQL Injection in query" "/api/stats?id=1' OR '1'='1" "" "403"
test_attack "SQL Injection UNION" "/api/stats?id=1 UNION SELECT * FROM users" "" "403"
test_attack "SQL Injection DROP" "/api/stats?name='; DROP TABLE users--" "" "403"

echo ""
echo "=== XSS Tests ==="
test_attack "XSS script tag" "/api/stats?name=<script>alert('XSS')</script>" "" "403"
test_attack "XSS onerror" "/api/stats?name=<img src=x onerror=alert(1)>" "" "403"
test_attack "XSS javascript:" "/api/stats?url=javascript:alert(1)" "" "403"

echo ""
echo "=== Path Traversal Tests ==="
test_attack "Path Traversal ../" "/api/../../../etc/passwd" "" "403"
test_attack "Path Traversal Windows" "/api/..\\..\\..\\windows\\system32\\config\\sam" "" "403"

echo ""
echo "=== Command Injection Tests ==="
test_attack "Command Injection pipe" "/api/stats?cmd=ls | cat /etc/passwd" "" "403"
test_attack "Command Injection semicolon" "/api/stats?cmd=; cat /etc/passwd" "" "403"
test_attack "Command Injection backtick" "/api/stats?cmd=\`cat /etc/passwd\`" "" "403"

echo ""
echo "=== File Upload Tests ==="
test_attack "Malicious file upload" "/api/upload" "file=malicious.php&content=<?php phpinfo(); ?>" "403"

echo ""
echo "=== Rate Limiting Tests ==="
echo -n "Testing rate limiting on login... "
for i in {1..15}; do
    curl -k -s -o /dev/null -X POST -d "username=test&password=test" "$BASE_URL/api/auth/login"
done
response=$(curl -k -s -o /dev/null -w "%{http_code}" -X POST -d "username=test&password=test" "$BASE_URL/api/auth/login")

if [ "$response" == "429" ]; then
    echo "✅ PASSED (HTTP 429 - Too Many Requests)"
    ((PASSED++))
else
    echo "❌ FAILED (Expected 429, got $response)"
    ((FAILED++))
fi

echo ""
echo "=== Legitimate Request Tests ==="
test_attack "Legitimate API call" "/api/health" "" "200"
test_attack "Legitimate login page" "/login.html" "" "200"
test_attack "Legitimate dashboard" "/index.html" "" "200"

echo ""
echo "=== Scanner Detection Tests ==="
echo -n "Testing scanner detection... "
response=$(curl -k -s -o /dev/null -w "%{http_code}" -H "User-Agent: sqlmap/1.0" "$BASE_URL/api/stats")

if [ "$response" == "403" ]; then
    echo "✅ PASSED (HTTP 403 - Scanner blocked)"
    ((PASSED++))
else
    echo "❌ FAILED (Expected 403, got $response)"
    ((FAILED++))
fi

echo ""
echo "=== Summary ==="
echo "✅ Passed: $PASSED"
echo "❌ Failed: $FAILED"
echo ""

if [ $FAILED -eq 0 ]; then
    echo "🎉 All tests passed!"
    exit 0
else
    echo "⚠️  Some tests failed. Check WAF configuration."
    exit 1
fi
