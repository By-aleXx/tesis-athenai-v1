"""
CloudWatch Alarms for AthenAI
Creates critical, warning, and info alarms with SNS notifications
"""

import boto3
import os
import json
from typing import Dict, List, Optional

class CloudWatchAlarms:
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
        self.alarms = {}
        self.sns_topics = self.load_sns_topics()
    
    def load_sns_topics(self) -> Dict[str, str]:
        """Load SNS topic ARNs from file"""
        try:
            with open('sns_topics.json', 'r') as f:
                topics = json.load(f)
            print(f"✅ Loaded {len(topics)} SNS topics")
            return topics
        except FileNotFoundError:
            print("⚠️  No SNS topics found. Run sns_setup.py first!")
            return {}
        except Exception as e:
            print(f"❌ Error loading SNS topics: {e}")
            return {}
    
    def create_alarm(
        self,
        name: str,
        metric_name: str,
        threshold: float,
        comparison: str,
        period: int,
        evaluation_periods: int,
        statistic: str,
        description: str,
        sns_topic_name: Optional[str] = None,
        dimensions: Optional[List[Dict[str, str]]] = None
    ) -> str:
        """Create a CloudWatch alarm"""
        try:
            alarm_actions = []
            if sns_topic_name and sns_topic_name in self.sns_topics:
                alarm_actions = [self.sns_topics[sns_topic_name]]
            
            self.cloudwatch.put_metric_alarm(
                AlarmName=name,
                ComparisonOperator=comparison,
                EvaluationPeriods=evaluation_periods,
                MetricName=metric_name,
                Namespace=self.namespace,
                Period=period,
                Statistic=statistic,
                Threshold=threshold,
                ActionsEnabled=True,
                AlarmActions=alarm_actions,
                AlarmDescription=description,
                Dimensions=dimensions or [],
                TreatMissingData='notBreaching'
            )
            
            self.alarms[name] = {
                'metric': metric_name,
                'threshold': threshold,
                'sns_topic': sns_topic_name
            }
            
            print(f"✅ Created alarm: {name}")
            return name
        
        except Exception as e:
            print(f"❌ Error creating alarm {name}: {e}")
            return None
    
    def create_critical_alarms(self):
        """Create critical alarms (SNS critical topic)"""
        print("🔴 Creating CRITICAL alarms...")
        
        # 1. High Error Rate (>5% in 5 min)
        self.create_alarm(
            name='AthenAI-HighErrorRate-Critical',
            metric_name='ErrorRate',
            threshold=5.0,
            comparison='GreaterThanThreshold',
            period=300,  # 5 minutes
            evaluation_periods=1,
            statistic='Sum',
            description='CRITICAL: Error rate exceeded 5% in 5 minutes',
            sns_topic_name='athenai-critical-alerts'
        )
        
        # 2. High Latency (P95 >500ms for 5 min)
        self.create_alarm(
            name='AthenAI-HighLatency-Critical',
            metric_name='APILatency',
            threshold=500.0,
            comparison='GreaterThanThreshold',
            period=300,
            evaluation_periods=1,
            statistic='p95',
            description='CRITICAL: P95 latency exceeded 500ms for 5 minutes',
            sns_topic_name='athenai-critical-alerts'
        )
        
        # 3. High Threat Rate (>50 threats/min)
        self.create_alarm(
            name='AthenAI-HighThreatRate-Critical',
            metric_name='ThreatDetectionRate',
            threshold=50.0,
            comparison='GreaterThanThreshold',
            period=60,  # 1 minute
            evaluation_periods=5,
            statistic='Sum',
            description='CRITICAL: More than 50 threats detected per minute',
            sns_topic_name='athenai-critical-alerts'
        )
        
        # 4. Database Latency Spike (>1000ms)
        self.create_alarm(
            name='AthenAI-DatabaseLatencySpike-Critical',
            metric_name='DatabaseLatency',
            threshold=1000.0,
            comparison='GreaterThanThreshold',
            period=300,
            evaluation_periods=1,
            statistic='Average',
            description='CRITICAL: Database latency exceeded 1000ms',
            sns_topic_name='athenai-critical-alerts'
        )
        
        # 5. ML Inference Failure (>100ms for 5 min)
        self.create_alarm(
            name='AthenAI-MLInferenceLatency-Critical',
            metric_name='MLInferenceLatency',
            threshold=100.0,
            comparison='GreaterThanThreshold',
            period=300,
            evaluation_periods=1,
            statistic='p95',
            description='CRITICAL: ML inference latency exceeded 100ms',
            sns_topic_name='athenai-critical-alerts'
        )
    
    def create_warning_alarms(self):
        """Create warning alarms (SNS warning topic)"""
        print("🟡 Creating WARNING alarms...")
        
        # 6. Moderate Error Rate (>2% in 10 min)
        self.create_alarm(
            name='AthenAI-ModerateErrorRate-Warning',
            metric_name='ErrorRate',
            threshold=2.0,
            comparison='GreaterThanThreshold',
            period=600,  # 10 minutes
            evaluation_periods=1,
            statistic='Sum',
            description='WARNING: Error rate exceeded 2% in 10 minutes',
            sns_topic_name='athenai-warning-alerts'
        )
        
        # 7. Moderate Latency (P95 >300ms for 10 min)
        self.create_alarm(
            name='AthenAI-ModerateLatency-Warning',
            metric_name='APILatency',
            threshold=300.0,
            comparison='GreaterThanThreshold',
            period=600,
            evaluation_periods=1,
            statistic='p95',
            description='WARNING: P95 latency exceeded 300ms for 10 minutes',
            sns_topic_name='athenai-warning-alerts'
        )
        
        # 8. Low Cache Hit Rate (<80% for 15 min)
        self.create_alarm(
            name='AthenAI-LowCacheHitRate-Warning',
            metric_name='CacheHitRate',
            threshold=80.0,
            comparison='LessThanThreshold',
            period=900,  # 15 minutes
            evaluation_periods=1,
            statistic='Average',
            description='WARNING: Cache hit rate below 80% for 15 minutes',
            sns_topic_name='athenai-warning-alerts'
        )
        
        # 9. High False Positive Rate (>10 in 10 min)
        self.create_alarm(
            name='AthenAI-HighFalsePositiveRate-Warning',
            metric_name='FalsePositiveRate',
            threshold=10.0,
            comparison='GreaterThanThreshold',
            period=600,
            evaluation_periods=1,
            statistic='Sum',
            description='WARNING: False positive rate exceeded 10 in 10 minutes',
            sns_topic_name='athenai-warning-alerts'
        )
        
        # 10. Moderate Threat Rate (>20 threats/min)
        self.create_alarm(
            name='AthenAI-ModerateThreatRate-Warning',
            metric_name='ThreatDetectionRate',
            threshold=20.0,
            comparison='GreaterThanThreshold',
            period=60,
            evaluation_periods=5,
            statistic='Sum',
            description='WARNING: More than 20 threats detected per minute',
            sns_topic_name='athenai-warning-alerts'
        )
    
    def create_info_alarms(self):
        """Create info alarms (no SNS, CloudWatch only)"""
        print("🔵 Creating INFO alarms...")
        
        # 11. Low ML Confidence (<70% for 30 min)
        self.create_alarm(
            name='AthenAI-LowMLConfidence-Info',
            metric_name='MLConfidence',
            threshold=70.0,
            comparison='LessThanThreshold',
            period=1800,  # 30 minutes
            evaluation_periods=1,
            statistic='Average',
            description='INFO: ML confidence below 70% for 30 minutes (possible model drift)',
            sns_topic_name='athenai-info-alerts'
        )
        
        # 12. High Request Rate (>1000 req/min)
        self.create_alarm(
            name='AthenAI-HighRequestRate-Info',
            metric_name='RequestCount',
            threshold=1000.0,
            comparison='GreaterThanThreshold',
            period=60,
            evaluation_periods=5,
            statistic='Sum',
            description='INFO: Request rate exceeded 1000 per minute (unusual traffic)',
            sns_topic_name='athenai-info-alerts'
        )
    
    def delete_alarm(self, name: str):
        """Delete a CloudWatch alarm"""
        try:
            self.cloudwatch.delete_alarms(AlarmNames=[name])
            if name in self.alarms:
                del self.alarms[name]
            print(f"✅ Deleted alarm: {name}")
        except Exception as e:
            print(f"❌ Error deleting alarm {name}: {e}")
    
    def list_alarms(self) -> List[str]:
        """List all CloudWatch alarms"""
        try:
            response = self.cloudwatch.describe_alarms(
                AlarmNamePrefix='AthenAI-'
            )
            alarms = [a['AlarmName'] for a in response.get('MetricAlarms', [])]
            print(f"🚨 Found {len(alarms)} alarms:")
            for name in alarms:
                print(f"   - {name}")
            return alarms
        except Exception as e:
            print(f"❌ Error listing alarms: {e}")
            return []
    
    def setup_all_alarms(self):
        """Setup all AthenAI alarms"""
        print("🚀 Setting up CloudWatch Alarms for AthenAI...")
        print()
        
        if not self.sns_topics:
            print("⚠️  No SNS topics found. Alarms will be created without notifications.")
            print("   Run: python sns_setup.py --email your@email.com")
            print()
        
        # Create alarms
        self.create_critical_alarms()
        print()
        self.create_warning_alarms()
        print()
        self.create_info_alarms()
        
        print()
        print("✅ All alarms created!")
        print()
        print("🚨 Alarms Summary:")
        print(f"   Critical: 5 alarms")
        print(f"   Warning: 5 alarms")
        print(f"   Info: 2 alarms")
        print(f"   Total: {len(self.alarms)} alarms")
        print()
        print("💡 View alarms in AWS CloudWatch Console:")
        print("   https://console.aws.amazon.com/cloudwatch/home?region=us-east-1#alarmsV2:")


def main():
    """Main setup function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Setup CloudWatch Alarms for AthenAI')
    parser.add_argument('--production', action='store_true', help='Use production AWS (not LocalStack)')
    parser.add_argument('--list', action='store_true', help='List existing alarms')
    parser.add_argument('--delete', type=str, help='Delete alarm by name')
    
    args = parser.parse_args()
    
    # Initialize alarms
    alarms = CloudWatchAlarms(use_localstack=not args.production)
    
    if args.list:
        alarms.list_alarms()
    elif args.delete:
        alarms.delete_alarm(args.delete)
    else:
        alarms.setup_all_alarms()


if __name__ == '__main__':
    main()
