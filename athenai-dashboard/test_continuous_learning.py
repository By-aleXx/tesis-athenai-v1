"""
Test script for Continuous Learning System
Generates benign and malicious requests to validate feedback and metrics
"""

import requests
import time
import json
from datetime import datetime

BASE_URL = "http://localhost:5000"

# ANSI color codes for terminal output
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def print_header(text):
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*80}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{text.center(80)}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'='*80}{Colors.RESET}\n")

def print_success(text):
    print(f"{Colors.GREEN}✓ {text}{Colors.RESET}")

def print_warning(text):
    print(f"{Colors.YELLOW}⚠ {text}{Colors.RESET}")

def print_error(text):
    print(f"{Colors.RED}✗ {text}{Colors.RESET}")

def print_info(text):
    print(f"{Colors.BLUE}ℹ {text}{Colors.RESET}")

# Test cases
benign_requests = [
    "/api/stats",
    "/api/traffic?limit=10",
    "/api/alerts?page=1",
    "/api/health",
    "/api/system-health",
    "/api/traffic-stats",
    "/api/continuous-learning/stats",
]

malicious_requests = [
    "/api/test?id=1' OR '1'='1",
    "/api/test?name=<script>alert('xss')</script>",
    "/api/test?query='; DROP TABLE users--",
    "/api/test?input=../../../etc/passwd",
    "/api/test?cmd=cat /etc/passwd",
    "/api/test?search=<img src=x onerror=alert(1)>",
    "/api/test?filter=' UNION SELECT * FROM users--",
]

def check_server():
    """Check if server is running"""
    try:
        response = requests.get(f"{BASE_URL}/api/health", timeout=5)
        return response.status_code == 200
    except:
        return False

def get_initial_stats():
    """Get initial continuous learning stats"""
    try:
        response = requests.get(f"{BASE_URL}/api/continuous-learning/stats")
        if response.status_code == 200:
            return response.json()
        return None
    except Exception as e:
        print_error(f"Error getting initial stats: {e}")
        return None

def generate_benign_requests(count=10):
    """Generate benign requests"""
    print_info(f"Generating {count} benign requests...")
    
    successful = 0
    failed = 0
    
    for i in range(count):
        endpoint = benign_requests[i % len(benign_requests)]
        try:
            response = requests.get(f"{BASE_URL}{endpoint}", timeout=5)
            if response.status_code in [200, 404]:  # 404 is ok for test endpoints
                successful += 1
                if (i + 1) % 10 == 0:
                    print_success(f"  Progress: {i + 1}/{count} requests sent")
            else:
                failed += 1
        except Exception as e:
            failed += 1
            if failed < 5:  # Only show first few errors
                print_warning(f"  Request failed: {e}")
        
        time.sleep(0.05)  # Small delay to avoid overwhelming server
    
    print_success(f"Benign requests completed: {successful} successful, {failed} failed")
    return successful, failed

def generate_malicious_requests(count=10):
    """Generate malicious requests"""
    print_info(f"Generating {count} malicious requests...")
    
    successful = 0
    blocked = 0
    failed = 0
    
    for i in range(count):
        endpoint = malicious_requests[i % len(malicious_requests)]
        try:
            response = requests.get(f"{BASE_URL}{endpoint}", timeout=5)
            if response.status_code == 403:
                blocked += 1
                if (i + 1) % 5 == 0:
                    print_warning(f"  Progress: {i + 1}/{count} requests sent ({blocked} blocked)")
            elif response.status_code in [200, 404]:
                successful += 1
            else:
                failed += 1
        except Exception as e:
            failed += 1
            if failed < 5:
                print_warning(f"  Request failed: {e}")
        
        time.sleep(0.05)
    
    print_success(f"Malicious requests completed: {blocked} blocked, {successful} passed, {failed} failed")
    return blocked, successful, failed

def check_stats_update(initial_stats, final_stats):
    """Check if stats were updated"""
    print_header("VALIDATING METRICS UPDATE")
    
    if not initial_stats or not final_stats:
        print_error("Could not retrieve stats for comparison")
        return False
    
    # Check buffer size
    initial_buffer = initial_stats.get('buffer_size', 0)
    final_buffer = final_stats.get('buffer_size', 0)
    buffer_increase = final_buffer - initial_buffer
    
    print_info(f"Buffer size: {initial_buffer} → {final_buffer} (+{buffer_increase})")
    
    if buffer_increase > 0:
        print_success(f"✓ Buffer increased by {buffer_increase} samples")
    else:
        print_warning("⚠ Buffer did not increase (feedback might not be working)")
    
    # Check other metrics
    print_info(f"Buffer percentage: {final_stats.get('buffer_percentage', 0):.1f}%")
    print_info(f"Total retrains: {final_stats.get('total_retrains', 0)}")
    print_info(f"Drift status: {final_stats.get('drift_status', 'UNKNOWN')}")
    print_info(f"CL enabled: {final_stats.get('continuous_learning_enabled', False)}")
    
    # Model performance
    perf = final_stats.get('model_performance', {})
    print_info(f"Model Performance:")
    print_info(f"  - F1-Score: {perf.get('f1_score', 0):.2f}%")
    print_info(f"  - Accuracy: {perf.get('accuracy', 0):.2f}%")
    print_info(f"  - Precision: {perf.get('precision', 0):.2f}%")
    print_info(f"  - Recall: {perf.get('recall', 0):.2f}%")
    
    return buffer_increase > 0

def main():
    print_header("CONTINUOUS LEARNING SYSTEM TEST")
    print_info(f"Test started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print_info(f"Target server: {BASE_URL}")
    
    # Check if server is running
    print_header("CHECKING SERVER STATUS")
    if not check_server():
        print_error("Server is not running!")
        print_info("Please start the server with: python api_backend.py")
        return
    
    print_success("Server is running")
    
    # Get initial stats
    print_header("GETTING INITIAL STATS")
    initial_stats = get_initial_stats()
    if initial_stats:
        print_success("Initial stats retrieved")
        print_info(f"Initial buffer size: {initial_stats.get('buffer_size', 0)}")
    else:
        print_warning("Could not retrieve initial stats (continuing anyway)")
    
    # Generate benign requests
    print_header("GENERATING BENIGN REQUESTS")
    benign_success, benign_failed = generate_benign_requests(100)
    
    # Wait a bit
    print_info("Waiting 2 seconds...")
    time.sleep(2)
    
    # Generate malicious requests
    print_header("GENERATING MALICIOUS REQUESTS")
    mal_blocked, mal_success, mal_failed = generate_malicious_requests(50)
    
    # Wait for processing
    print_info("Waiting 3 seconds for processing...")
    time.sleep(3)
    
    # Get final stats
    print_header("GETTING FINAL STATS")
    final_stats = get_initial_stats()
    if final_stats:
        print_success("Final stats retrieved")
        print_info(f"Final buffer size: {final_stats.get('buffer_size', 0)}")
    
    # Validate stats update
    stats_updated = check_stats_update(initial_stats, final_stats)
    
    # Summary
    print_header("TEST SUMMARY")
    print_info(f"Benign requests: {benign_success} successful, {benign_failed} failed")
    print_info(f"Malicious requests: {mal_blocked} blocked, {mal_success} passed, {mal_failed} failed")
    
    if stats_updated:
        print_success("✓ Continuous learning system is working correctly!")
        print_success("✓ Feedback is being sent to AI Engine")
        print_success("✓ Metrics are being updated")
    else:
        print_warning("⚠ Some issues detected:")
        print_warning("  - Buffer might not be increasing")
        print_warning("  - Check backend logs for feedback messages")
    
    print_info(f"\nTest completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print_info("\nNext steps:")
    print_info("  1. Check dashboard UI at http://localhost:5000")
    print_info("  2. Navigate to 'ML Status' tab (last icon in sidebar)")
    print_info("  3. Verify that metrics are displayed correctly")
    print_info("  4. Check backend logs for '📚 Feedback sent to AI Engine' messages")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print_error("\n\nTest interrupted by user")
    except Exception as e:
        print_error(f"\n\nTest failed with error: {e}")
        import traceback
        traceback.print_exc()
