#!/usr/bin/env python3
"""
Test Lambda function locally without deploying.
"""

import sys
import os
import json
import time

# Add the function directory to path
sys.path.insert(0, 'functions/security/agentcore_assessments')

# Set environment variables
os.environ['AIML_ASSESSMENT_BUCKET_NAME'] = 'resco-aiml-assessment-aimlassessmentbucket-twpll3epfpql'

# Import the Lambda handler
from app import lambda_handler

# Create a test event
event = {
    'Execution': {
        'Name': 'test-execution-local-' + str(int(time.time()))
    }
}

# Create a mock context
class MockContext:
    def __init__(self):
        self.function_name = 'AgentCoreSecurityAssessmentFunction'
        self.memory_limit_in_mb = 1024
        self.invoked_function_arn = 'arn:aws:lambda:us-east-1:914787431788:function:test'
        self.aws_request_id = 'test-request-id'

context = MockContext()

print("="*80)
print("Testing Lambda function locally")
print("="*80)
print(f"\nEvent: {json.dumps(event, indent=2)}")
print(f"\nBucket: {os.environ['AIML_ASSESSMENT_BUCKET_NAME']}")
print("\n" + "="*80)
print("Executing lambda_handler...")
print("="*80 + "\n")

# Execute the handler
try:
    response = lambda_handler(event, context)
    
    print("\n" + "="*80)
    print("Lambda execution completed")
    print("="*80)
    print(f"\nStatus Code: {response['statusCode']}")
    print(f"\nResponse Body:")
    print(json.dumps(json.loads(response['body']), indent=2))
    
    if response['statusCode'] == 200:
        print("\n✓ SUCCESS")
        sys.exit(0)
    else:
        print("\n✗ FAILED")
        sys.exit(1)
        
except Exception as e:
    print("\n" + "="*80)
    print("Lambda execution failed")
    print("="*80)
    print(f"\n✗ Error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
