"""
CloudWatch Dashboards for AthenAI
Creates 3 dashboards: Security, ML Performance, System Performance
"""

import boto3
import os
import json
from typing import Dict, List, Any

class CloudWatchDashboards:
    def __init__(self, use_localstack: bool = True):
        """Initialize CloudWatch client"""
        self.use_localstack = use_localstack
        
        if use_localstack:
            endpoint_url = os.environ['AWS_ENDPOINT_URL']
            self.cloudwatch = boto3.client(
                'cloudwatch',
                endpoint_url=endpoint_url,
                region_name=os.getenv('AWS_REGION', 'us-east-1'),
                aws_access_key_id=os.environ['AWS_ACCESS_KEY_ID'],
                aws_secret_access_key=os.environ['AWS_SECRET_ACCESS_KEY']
            )
        else:
            self.cloudwatch = boto3.client('cloudwatch', region_name=os.getenv('AWS_REGION', 'us-east-1'))
        
        self.namespace = 'AthenAI/Security'
        self.dashboards = {}
    
    def create_security_dashboard(self) -> str:
        """Create Security Overview Dashboard"""
        dashboard_body = {
            "widgets": [
                # Threats Over Time
                {
                    "type": "metric",
                    "properties": {
                        "metrics": [
                            [self.namespace, "ThreatDetectionRate", {"stat": "Sum", "label": "Threats Detected"}]
                        ],
                        "period": 300,
                        "stat": "Sum",
                        "region": "us-east-1",
                        "title": "Threats Over Time",
                        "yAxis": {"left": {"label": "Count"}},
                        "view": "timeSeries"
                    }
                },
                # Blocked IPs
                {
                    "type": "metric",
                    "properties": {
                        "metrics": [
                            [self.namespace, "BlockedRequests", {"stat": "Sum", "label": "Blocked Requests"}]
                        ],
                        "period": 300,
                        "stat": "Sum",
                        "region": "us-east-1",
                        "title": "Blocked Requests",
                        "yAxis": {"left": {"label": "Count"}},
                        "view": "timeSeries"
                    }
                },
                # Total Threats (Number)
                {
                    "type": "metric",
                    "properties": {
                        "metrics": [
                            [self.namespace, "ThreatDetectionRate", {"stat": "Sum"}]
                        ],
                        "period": 3600,
                        "stat": "Sum",
                        "region": "us-east-1",
                        "title": "Total Threats (Last Hour)",
                        "view": "singleValue"
                    }
                },
                # Total Blocked (Number)
                {
                    "type": "metric",
                    "properties": {
                        "metrics": [
                            [self.namespace, "BlockedRequests", {"stat": "Sum"}]
                        ],
                        "period": 3600,
                        "stat": "Sum",
                        "region": "us-east-1",
                        "title": "Total Blocked (Last Hour)",
                        "view": "singleValue"
                    }
                },
                # Error Rate
                {
                    "type": "metric",
                    "properties": {
                        "metrics": [
                            [self.namespace, "ErrorRate", {"stat": "Sum", "label": "Errors"}]
                        ],
                        "period": 300,
                        "stat": "Sum",
                        "region": "us-east-1",
                        "title": "Error Rate",
                        "yAxis": {"left": {"label": "Count"}},
                        "view": "timeSeries"
                    }
                },
                # Request Count
                {
                    "type": "metric",
                    "properties": {
                        "metrics": [
                            [self.namespace, "RequestCount", {"stat": "Sum", "label": "Total Requests"}]
                        ],
                        "period": 300,
                        "stat": "Sum",
                        "region": "us-east-1",
                        "title": "Request Count",
                        "yAxis": {"left": {"label": "Count"}},
                        "view": "timeSeries"
                    }
                }
            ]
        }
        
        return self.create_dashboard('AthenAI-Security-Dashboard', dashboard_body)
    
    def create_ml_dashboard(self) -> str:
        """Create ML Performance Dashboard"""
        dashboard_body = {
            "widgets": [
                # ML Inference Latency
                {
                    "type": "metric",
                    "properties": {
                        "metrics": [
                            [self.namespace, "MLInferenceLatency", {"stat": "Average", "label": "P50"}],
                            [self.namespace, "MLInferenceLatency", {"stat": "p95", "label": "P95"}],
                            [self.namespace, "MLInferenceLatency", {"stat": "p99", "label": "P99"}]
                        ],
                        "period": 300,
                        "stat": "Average",
                        "region": "us-east-1",
                        "title": "ML Inference Latency",
                        "yAxis": {"left": {"label": "Milliseconds"}},
                        "view": "timeSeries"
                    }
                },
                # ML Confidence
                {
                    "type": "metric",
                    "properties": {
                        "metrics": [
                            [self.namespace, "MLConfidence", {"stat": "Average", "label": "Avg Confidence"}]
                        ],
                        "period": 300,
                        "stat": "Average",
                        "region": "us-east-1",
                        "title": "ML Model Confidence",
                        "yAxis": {"left": {"label": "Percent"}},
                        "view": "timeSeries"
                    }
                },
                # Average Inference Time (Number)
                {
                    "type": "metric",
                    "properties": {
                        "metrics": [
                            [self.namespace, "MLInferenceLatency", {"stat": "Average"}]
                        ],
                        "period": 3600,
                        "stat": "Average",
                        "region": "us-east-1",
                        "title": "Avg Inference Time (ms)",
                        "view": "singleValue"
                    }
                },
                # Average Confidence (Number)
                {
                    "type": "metric",
                    "properties": {
                        "metrics": [
                            [self.namespace, "MLConfidence", {"stat": "Average"}]
                        ],
                        "period": 3600,
                        "stat": "Average",
                        "region": "us-east-1",
                        "title": "Avg Confidence (%)",
                        "view": "singleValue"
                    }
                },
                # False Positive Rate
                {
                    "type": "metric",
                    "properties": {
                        "metrics": [
                            [self.namespace, "FalsePositiveRate", {"stat": "Sum", "label": "False Positives"}]
                        ],
                        "period": 300,
                        "stat": "Sum",
                        "region": "us-east-1",
                        "title": "False Positive Rate",
                        "yAxis": {"left": {"label": "Count"}},
                        "view": "timeSeries"
                    }
                },
                # Threat Detection Rate
                {
                    "type": "metric",
                    "properties": {
                        "metrics": [
                            [self.namespace, "ThreatDetectionRate", {"stat": "Sum", "label": "Threats"}]
                        ],
                        "period": 300,
                        "stat": "Sum",
                        "region": "us-east-1",
                        "title": "Threat Detection Rate",
                        "yAxis": {"left": {"label": "Count"}},
                        "view": "timeSeries"
                    }
                }
            ]
        }
        
        return self.create_dashboard('AthenAI-ML-Dashboard', dashboard_body)
    
    def create_performance_dashboard(self) -> str:
        """Create System Performance Dashboard"""
        dashboard_body = {
            "widgets": [
                # API Latency
                {
                    "type": "metric",
                    "properties": {
                        "metrics": [
                            [self.namespace, "APILatency", {"stat": "Average", "label": "P50"}],
                            [self.namespace, "APILatency", {"stat": "p95", "label": "P95"}],
                            [self.namespace, "APILatency", {"stat": "p99", "label": "P99"}]
                        ],
                        "period": 300,
                        "stat": "Average",
                        "region": "us-east-1",
                        "title": "API Response Time",
                        "yAxis": {"left": {"label": "Milliseconds"}},
                        "view": "timeSeries"
                    }
                },
                # Request Rate
                {
                    "type": "metric",
                    "properties": {
                        "metrics": [
                            [self.namespace, "RequestCount", {"stat": "Sum", "label": "Requests"}]
                        ],
                        "period": 60,
                        "stat": "Sum",
                        "region": "us-east-1",
                        "title": "Request Rate (per minute)",
                        "yAxis": {"left": {"label": "Count"}},
                        "view": "timeSeries"
                    }
                },
                # Error Rate
                {
                    "type": "metric",
                    "properties": {
                        "metrics": [
                            [self.namespace, "ErrorRate", {"stat": "Sum", "label": "Errors"}],
                            [self.namespace, "RequestCount", {"stat": "Sum", "label": "Total Requests"}]
                        ],
                        "period": 300,
                        "stat": "Sum",
                        "region": "us-east-1",
                        "title": "Error Rate vs Requests",
                        "yAxis": {"left": {"label": "Count"}},
                        "view": "timeSeries"
                    }
                },
                # Current RPS (Number)
                {
                    "type": "metric",
                    "properties": {
                        "metrics": [
                            [self.namespace, "RequestCount", {"stat": "Sum"}]
                        ],
                        "period": 60,
                        "stat": "Sum",
                        "region": "us-east-1",
                        "title": "Current RPS",
                        "view": "singleValue"
                    }
                },
                # Database Latency
                {
                    "type": "metric",
                    "properties": {
                        "metrics": [
                            [self.namespace, "DatabaseLatency", {"stat": "Average", "label": "Avg DB Latency"}]
                        ],
                        "period": 300,
                        "stat": "Average",
                        "region": "us-east-1",
                        "title": "Database Latency",
                        "yAxis": {"left": {"label": "Milliseconds"}},
                        "view": "timeSeries"
                    }
                },
                # Cache Hit Rate
                {
                    "type": "metric",
                    "properties": {
                        "metrics": [
                            [self.namespace, "CacheHitRate", {"stat": "Sum", "label": "Cache Hits"}],
                            [self.namespace, "CacheMissRate", {"stat": "Sum", "label": "Cache Misses"}]
                        ],
                        "period": 300,
                        "stat": "Sum",
                        "region": "us-east-1",
                        "title": "Cache Hit vs Miss",
                        "yAxis": {"left": {"label": "Count"}},
                        "view": "timeSeries"
                    }
                }
            ]
        }
        
        return self.create_dashboard('AthenAI-Performance-Dashboard', dashboard_body)
    
    def create_dashboard(self, name: str, body: Dict[str, Any]) -> str:
        """Create or update a CloudWatch dashboard"""
        try:
            self.cloudwatch.put_dashboard(
                DashboardName=name,
                DashboardBody=json.dumps(body)
            )
            self.dashboards[name] = body
            print(f"✅ Created dashboard: {name}")
            return name
        except Exception as e:
            print(f"❌ Error creating dashboard {name}: {e}")
            return None
    
    def delete_dashboard(self, name: str):
        """Delete a CloudWatch dashboard"""
        try:
            self.cloudwatch.delete_dashboards(DashboardNames=[name])
            if name in self.dashboards:
                del self.dashboards[name]
            print(f"✅ Deleted dashboard: {name}")
        except Exception as e:
            print(f"❌ Error deleting dashboard {name}: {e}")
    
    def list_dashboards(self) -> List[str]:
        """List all CloudWatch dashboards"""
        try:
            response = self.cloudwatch.list_dashboards()
            dashboards = [d['DashboardName'] for d in response.get('DashboardEntries', [])]
            print(f"📊 Found {len(dashboards)} dashboards:")
            for name in dashboards:
                print(f"   - {name}")
            return dashboards
        except Exception as e:
            print(f"❌ Error listing dashboards: {e}")
            return []
    
    def setup_all_dashboards(self):
        """Setup all AthenAI dashboards"""
        print("🚀 Setting up CloudWatch Dashboards for AthenAI...")
        print()
        
        # Create dashboards
        self.create_security_dashboard()
        self.create_ml_dashboard()
        self.create_performance_dashboard()
        
        print()
        print("✅ All dashboards created!")
        print()
        print("📊 Dashboards:")
        for name in self.dashboards.keys():
            print(f"   - {name}")
        print()
        print("💡 View dashboards in AWS CloudWatch Console:")
        print("   https://console.aws.amazon.com/cloudwatch/home?region=us-east-1#dashboards:")


def main():
    """Main setup function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Setup CloudWatch Dashboards for AthenAI')
    parser.add_argument('--production', action='store_true', help='Use production AWS (not LocalStack)')
    parser.add_argument('--list', action='store_true', help='List existing dashboards')
    parser.add_argument('--delete', type=str, help='Delete dashboard by name')
    
    args = parser.parse_args()
    
    # Initialize dashboards
    dashboards = CloudWatchDashboards(use_localstack=not args.production)
    
    if args.list:
        dashboards.list_dashboards()
    elif args.delete:
        dashboards.delete_dashboard(args.delete)
    else:
        dashboards.setup_all_dashboards()


if __name__ == '__main__':
    main()
