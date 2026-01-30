#!/usr/bin/env python3
"""
Direct test of AgentCore API calls to debug permission issues.
"""

import boto3
import json
from botocore.config import Config
from botocore.exceptions import ClientError

# Configure boto3 with adaptive retry mode
boto3_config = Config(
    retries=dict(
        max_attempts=10,
        mode='adaptive'
    )
)

# Initialize AgentCore client
try:
    agentcore_client = boto3.client('bedrock-agentcore-control', config=boto3_config)
    print("✓ Successfully initialized bedrock-agentcore-control client")
except Exception as e:
    print(f"✗ Failed to initialize bedrock-agentcore-control client: {e}")
    exit(1)

# Get current identity
sts_client = boto3.client('sts')
identity = sts_client.get_caller_identity()
print(f"\n✓ Current identity:")
print(f"  Account: {identity['Account']}")
print(f"  ARN: {identity['Arn']}")
print(f"  UserId: {identity['UserId']}")

# Test 1: List Agent Runtimes
print("\n" + "="*80)
print("TEST 1: list_agent_runtimes()")
print("="*80)
try:
    response = agentcore_client.list_agent_runtimes()
    runtimes = response.get('agentRuntimes', [])
    print(f"✓ Successfully listed {len(runtimes)} runtimes")
    
    if runtimes:
        print("\nRuntimes found:")
        for runtime in runtimes:
            runtime_id = runtime.get('agentRuntimeId') or runtime.get('runtimeId')
            runtime_name = runtime.get('agentRuntimeName') or runtime.get('name')
            print(f"  - ID: {runtime_id}")
            print(f"    Name: {runtime_name}")
            print(f"    Keys in response: {list(runtime.keys())}")
    else:
        print("  No runtimes found")
        
except ClientError as e:
    print(f"✗ ClientError: {e.response['Error']['Code']}")
    print(f"  Message: {e.response['Error']['Message']}")
    exit(1)
except Exception as e:
    print(f"✗ Error: {e}")
    exit(1)

# Test 2: Get Agent Runtime details
if runtimes:
    print("\n" + "="*80)
    print("TEST 2: get_agent_runtime()")
    print("="*80)
    
    runtime_id = runtimes[0].get('agentRuntimeId') or runtimes[0].get('runtimeId')
    print(f"Testing with runtime ID: {runtime_id}")
    
    try:
        response = agentcore_client.get_agent_runtime(agentRuntimeId=runtime_id)
        print(f"✓ Successfully retrieved runtime details")
        print(f"\nTop-level keys in response:")
        for key in response.keys():
            print(f"  - {key}")
        
        print(f"\nFull response structure:")
        print(json.dumps(response, indent=2, default=str))
        
    except ClientError as e:
        print(f"✗ ClientError: {e.response['Error']['Code']}")
        print(f"  Message: {e.response['Error']['Message']}")
        print(f"\nFull error response:")
        print(json.dumps(e.response, indent=2, default=str))
    except Exception as e:
        print(f"✗ Error: {e}")

# Test 3: List Memories
print("\n" + "="*80)
print("TEST 3: list_memories()")
print("="*80)
try:
    response = agentcore_client.list_memories()
    memories = response.get('memories', [])
    print(f"✓ Successfully listed {len(memories)} memories")
    
    if memories:
        print("\nMemories found:")
        for memory in memories:
            memory_id = memory.get('memoryId') or memory.get('id')
            memory_name = memory.get('memoryName') or memory.get('name')
            print(f"  - ID: {memory_id}")
            print(f"    Name: {memory_name}")
            print(f"    Keys in response: {list(memory.keys())}")
    else:
        print("  No memories found")
        
except ClientError as e:
    print(f"✗ ClientError: {e.response['Error']['Code']}")
    print(f"  Message: {e.response['Error']['Message']}")
except Exception as e:
    print(f"✗ Error: {e}")

print("\n" + "="*80)
print("Test completed")
print("="*80)
