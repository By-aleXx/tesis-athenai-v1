"""
SNS Setup for AthenAI Observability
Creates SNS topics for critical, warning, and info notifications
"""

import boto3
import os
import json
from typing import Dict, List

class SNSSetup:
    def __init__(self, use_localstack: bool = True):
        """Initialize SNS client"""
        self.use_localstack = use_localstack
        
        if use_localstack:
            endpoint_url = os.environ['AWS_ENDPOINT_URL']
            self.sns = boto3.client(
                'sns',
                endpoint_url=endpoint_url,
                region_name=os.getenv('AWS_REGION', 'us-east-1'),
                aws_access_key_id=os.environ['AWS_ACCESS_KEY_ID'],
                aws_secret_access_key=os.environ['AWS_SECRET_ACCESS_KEY']
            )
        else:
            self.sns = boto3.client('sns', region_name=os.getenv('AWS_REGION', 'us-east-1'))
        
        self.topics = {}
    
    def create_topic(self, name: str, display_name: str) -> str:
        """Create SNS topic"""
        try:
            response = self.sns.create_topic(
                Name=name,
                Attributes={
                    'DisplayName': display_name
                },
                Tags=[
                    {'Key': 'Project', 'Value': 'AthenAI'},
                    {'Key': 'Component', 'Value': 'Observability'}
                ]
            )
            topic_arn = response['TopicArn']
            self.topics[name] = topic_arn
            print(f"✅ Created topic: {name} ({topic_arn})")
            return topic_arn
        except Exception as e:
            print(f"❌ Error creating topic {name}: {e}")
            return None
    
    def subscribe_email(self, topic_arn: str, email: str) -> str:
        """Subscribe email to topic"""
        try:
            response = self.sns.subscribe(
                TopicArn=topic_arn,
                Protocol='email',
                Endpoint=email
            )
            subscription_arn = response['SubscriptionArn']
            print(f"✅ Subscribed {email} to topic")
            print(f"   ⚠️  Check email for confirmation link!")
            return subscription_arn
        except Exception as e:
            print(f"❌ Error subscribing email: {e}")
            return None
    
    def subscribe_sms(self, topic_arn: str, phone: str) -> str:
        """Subscribe SMS to topic"""
        try:
            response = self.sns.subscribe(
                TopicArn=topic_arn,
                Protocol='sms',
                Endpoint=phone
            )
            subscription_arn = response['SubscriptionArn']
            print(f"✅ Subscribed {phone} to topic")
            return subscription_arn
        except Exception as e:
            print(f"❌ Error subscribing SMS: {e}")
            return None
    
    def publish_test_message(self, topic_arn: str, subject: str, message: str):
        """Publish test message to topic"""
        try:
            response = self.sns.publish(
                TopicArn=topic_arn,
                Subject=subject,
                Message=message
            )
            message_id = response['MessageId']
            print(f"✅ Published test message: {message_id}")
            return message_id
        except Exception as e:
            print(f"❌ Error publishing message: {e}")
            return None
    
    def setup_all_topics(self, email: str = None, phone: str = None) -> Dict[str, str]:
        """Setup all SNS topics"""
        print("🚀 Setting up SNS topics for AthenAI...")
        print()
        
        # Create topics
        topics_config = [
            ('athenai-critical-alerts', 'AthenAI Critical Alerts'),
            ('athenai-warning-alerts', 'AthenAI Warning Alerts'),
            ('athenai-info-alerts', 'AthenAI Info Alerts')
        ]
        
        for topic_name, display_name in topics_config:
            self.create_topic(topic_name, display_name)
        
        print()
        
        # Subscribe email if provided
        if email:
            print(f"📧 Subscribing email: {email}")
            for topic_name, topic_arn in self.topics.items():
                self.subscribe_email(topic_arn, email)
            print()
        
        # Subscribe SMS if provided (critical only)
        if phone:
            print(f"📱 Subscribing SMS: {phone}")
            critical_arn = self.topics.get('athenai-critical-alerts')
            if critical_arn:
                self.subscribe_sms(critical_arn, phone)
            print()
        
        # Save topic ARNs to file
        self.save_topic_arns()
        
        return self.topics
    
    def save_topic_arns(self):
        """Save topic ARNs to JSON file"""
        try:
            with open('sns_topics.json', 'w') as f:
                json.dump(self.topics, f, indent=2)
            print("✅ Saved topic ARNs to sns_topics.json")
        except Exception as e:
            print(f"❌ Error saving topic ARNs: {e}")
    
    def load_topic_arns(self) -> Dict[str, str]:
        """Load topic ARNs from JSON file"""
        try:
            with open('sns_topics.json', 'r') as f:
                self.topics = json.load(f)
            print(f"✅ Loaded {len(self.topics)} topic ARNs")
            return self.topics
        except FileNotFoundError:
            print("⚠️  No saved topic ARNs found")
            return {}
        except Exception as e:
            print(f"❌ Error loading topic ARNs: {e}")
            return {}
    
    def test_notifications(self):
        """Send test notifications to all topics"""
        print("🧪 Sending test notifications...")
        print()
        
        test_messages = [
            ('athenai-critical-alerts', 'CRITICAL: Test Alert', 
             'This is a test critical alert from AthenAI. If you receive this, notifications are working!'),
            ('athenai-warning-alerts', 'WARNING: Test Alert',
             'This is a test warning alert from AthenAI.'),
            ('athenai-info-alerts', 'INFO: Test Alert',
             'This is a test info alert from AthenAI.')
        ]
        
        for topic_name, subject, message in test_messages:
            topic_arn = self.topics.get(topic_name)
            if topic_arn:
                self.publish_test_message(topic_arn, subject, message)
        
        print()
        print("✅ Test notifications sent!")
        print("   📧 Check your email for test messages")
        print("   📱 Check your phone for SMS (critical only)")


def main():
    """Main setup function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Setup SNS topics for AthenAI')
    parser.add_argument('--email', type=str, help='Email address for notifications')
    parser.add_argument('--phone', type=str, help='Phone number for SMS (format: +1234567890)')
    parser.add_argument('--test', action='store_true', help='Send test notifications')
    parser.add_argument('--production', action='store_true', help='Use production AWS (not LocalStack)')
    
    args = parser.parse_args()
    
    # Initialize SNS setup
    sns_setup = SNSSetup(use_localstack=not args.production)
    
    # Setup topics
    sns_setup.setup_all_topics(email=args.email, phone=args.phone)
    
    # Send test notifications if requested
    if args.test:
        print()
        sns_setup.test_notifications()
    
    print()
    print("✅ SNS setup complete!")
    print()
    print("📋 Topic ARNs:")
    for name, arn in sns_setup.topics.items():
        print(f"   {name}: {arn}")
    print()
    print("💡 Next steps:")
    print("   1. Check your email and confirm subscriptions")
    print("   2. Run with --test flag to send test notifications")
    print("   3. Use topic ARNs in CloudWatch alarms")


if __name__ == '__main__':
    main()
