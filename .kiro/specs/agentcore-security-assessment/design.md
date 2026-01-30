# Amazon Bedrock AgentCore Security Assessment - Design Document

## 1. Architecture Overview

### 1.1 System Context
The AgentCore security assessment integrates into the existing ReSCO AI/ML assessment framework as a third parallel assessment branch alongside Bedrock and SageMaker assessments.

```
Step Functions Workflow
├── IAMPermissionCachingFunction (runs first)
├── Parallel Execution
│   ├── BedrockSecurityAssessmentFunction
│   ├── SageMakerSecurityAssessmentFunction
│   └── AgentCoreSecurityAssessmentFunction (NEW)
└── GenerateConsolidatedReportFunction (runs last)
```

### 1.2 Component Architecture

**Lambda Function**: `AgentCoreSecurityAssessmentFunction`
- **Runtime**: Python 3.12
- **Timeout**: 10 minutes (600 seconds)
- **Memory**: 1024 MB
- **Handler**: `app.lambda_handler`

**Dependencies**:
- boto3 >= 1.34.0 (for bedrock-agentcore-control API support)
- pydantic >= 2.0 (schema validation)
- typing-extensions (type hints)

**AWS Service Integrations**:
- bedrock-agentcore-control (primary API)
- IAM (permission validation)
- EC2 (VPC validation)
- ECR (encryption checks)
- CloudWatch Logs (observability checks)
- S3 (results storage)

### 1.3 Data Flow

```
1. Lambda receives execution_id from Step Functions
2. Retrieve cached IAM permissions from S3
3. Execute 8 assessment checks in sequence
4. Collect findings with Pydantic validation
5. Generate CSV report
6. Upload to S3: agentcore_security_report_{execution_id}.csv
7. Return success/failure status
```

## 2. Assessment Check Specifications

### 2.1 Check: AgentCore VPC Configuration

**Function**: `check_agentcore_vpc_configuration()`

**Purpose**: Validate VPC configuration for AgentCore Runtimes, Code Interpreters, and Browser Tools

**API Calls**:
```python
bedrock_agentcore_client.list_runtimes()
bedrock_agentcore_client.describe_runtime(runtimeId=...)
bedrock_agentcore_client.list_code_interpreters()
bedrock_agentcore_client.describe_code_interpreter(codeInterpreterId=...)
bedrock_agentcore_client.list_browser_tools()
bedrock_agentcore_client.describe_browser_tool(browserToolId=...)
ec2_client.describe_subnets(SubnetIds=[...])
ec2_client.describe_route_tables(Filters=[...])
ec2_client.describe_vpc_endpoints(VpcEndpointIds=[...])
```

**Validation Logic**:
1. List all AgentCore Runtimes
   - Check if `vpcConfig` exists
   - If missing: HIGH severity finding
   - If present: validate subnet configuration

2. For each Runtime with VPC:
   - Validate subnets are private (no direct internet route)
   - Check for NAT gateway in route tables
   - Verify required VPC endpoints exist:
     * com.amazonaws.{region}.ecr.api
     * com.amazonaws.{region}.ecr.dkr
     * com.amazonaws.{region}.s3
     * com.amazonaws.{region}.logs

3. Repeat for Code Interpreters and Browser Tools

**Findings**:
- **HIGH**: Runtime/Code Interpreter/Browser Tool without VPC configuration
- **MEDIUM**: VPC configured but missing required endpoints
- **MEDIUM**: Subnets are public (have internet gateway route)
- **LOW**: NAT gateway not configured (limits outbound access)

**Error Handling**:
- Handle `ResourceNotFoundException` gracefully (no resources = N/A finding)
- Handle API throttling with exponential backoff
- Log errors but continue with other checks



### 2.2 Check: AgentCore IAM Full Access Policies

**Function**: `check_agentcore_full_access_roles(permission_cache)`

**Purpose**: Identify roles with overly permissive AgentCore access

**Input**: `permission_cache` from IAMPermissionCachingFunction

**Validation Logic**:
1. Iterate through `permission_cache["role_permissions"]`
2. Check attached_policies for:
   - `BedrockAgentCoreFullAccess` (AWS managed policy)
   - Custom policies with `bedrock-agentcore:*` actions
3. Check inline_policies for wildcard AgentCore permissions

**Findings**:
- **HIGH**: Role has BedrockAgentCoreFullAccess policy
- **HIGH**: Role has custom policy with `bedrock-agentcore:*` on `Resource: "*"`

**Resolution**: Replace with least-privilege policies scoped to specific resources

**Reference**: https://docs.aws.amazon.com/bedrock/latest/userguide/security-iam-awsmanpol.html

### 2.3 Check: Stale AgentCore Access

**Function**: `check_stale_agentcore_access(permission_cache)`

**Purpose**: Identify IAM principals with AgentCore permissions but no recent usage

**Input**: `permission_cache` from IAMPermissionCachingFunction

**API Calls**:
```python
iam_client.generate_service_last_accessed_details(Arn=principal_arn)
iam_client.get_service_last_accessed_details(JobId=job_id)
```

**Validation Logic**:
1. Identify all roles/users with AgentCore permissions from cache
2. For each principal:
   - Generate service last accessed report
   - Wait for job completion (max 30 seconds)
   - Check last access to "Amazon Bedrock AgentCore"
   - Flag if last_accessed > 60 days or never accessed

**Findings**:
- **MEDIUM**: Principal hasn't accessed AgentCore in 60+ days
- **MEDIUM**: Principal has permissions but never accessed AgentCore

**Resolution**: Review and remove unused permissions following least privilege

**Reference**: https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_last-accessed.html

### 2.4 Check: AgentCore Observability Configuration

**Function**: `check_agentcore_observability()`

**Purpose**: Verify CloudWatch Logs, X-Ray tracing, and metrics are configured

**API Calls**:
```python
bedrock_agentcore_client.list_runtimes()
bedrock_agentcore_client.describe_runtime(runtimeId=...)
logs_client.describe_log_groups(logGroupNamePrefix='/aws/bedrock/agentcore/')
xray_client.get_trace_summaries(...)
cloudwatch_client.list_metrics(Namespace='AWS/BedrockAgentCore')
```

**Validation Logic**:
1. For each Runtime:
   - Check if `loggingConfig.cloudWatchLogsConfig` is configured
   - Verify log group exists and is not empty
   - Check if X-Ray tracing is enabled (`tracingConfig.enabled`)

2. Check CloudWatch custom metrics:
   - Verify metrics are being published to AWS/BedrockAgentCore namespace
   - Check for runtime-specific metrics

**Findings**:
- **MEDIUM**: Runtime without CloudWatch Logs configuration
- **MEDIUM**: Runtime without X-Ray tracing enabled
- **LOW**: No custom metrics being published

**Resolution**: Enable comprehensive observability for monitoring and troubleshooting

**Reference**: https://aws.github.io/bedrock-agentcore-starter-toolkit/user-guide/observability/

### 2.5 Check: AgentCore Encryption Configuration

**Function**: `check_agentcore_encryption()`

**Purpose**: Validate encryption at rest for ECR repositories and S3 buckets

**API Calls**:
```python
ecr_client.describe_repositories()
ecr_client.get_repository_policy(repositoryName=...)
s3_client.list_buckets()
s3_client.get_bucket_encryption(Bucket=...)
s3_client.get_bucket_tagging(Bucket=...)
```

**Validation Logic**:
1. Identify ECR repositories used by AgentCore:
   - Look for repositories with tag `bedrock-agentcore:runtime` or similar
   - Check encryption configuration
   - Verify KMS key usage (AWS-managed vs customer-managed)

2. Identify S3 buckets used for Browser Tool recordings:
   - List buckets with tag `bedrock-agentcore:browser-recordings`
   - Check bucket encryption configuration
   - Verify server-side encryption is enabled

**Findings**:
- **HIGH**: ECR repository without encryption
- **HIGH**: S3 bucket without encryption
- **LOW**: Using AWS-managed keys instead of customer-managed keys

**Resolution**: Enable encryption with customer-managed KMS keys for better control

**Reference**: https://docs.aws.amazon.com/bedrock/latest/userguide/key-management.html



### 2.6 Check: Browser Tool Recording Configuration

**Function**: `check_browser_tool_recording()`

**Purpose**: Verify Browser Tool session recording is enabled and properly configured

**API Calls**:
```python
bedrock_agentcore_client.list_browser_tools()
bedrock_agentcore_client.describe_browser_tool(browserToolId=...)
s3_client.head_bucket(Bucket=...)
s3_client.get_bucket_versioning(Bucket=...)
```

**Validation Logic**:
1. List all Browser Tools
2. For each Browser Tool:
   - Check if `recordingConfig.enabled` is true
   - Verify `recordingConfig.s3BucketName` is configured
   - Validate S3 bucket exists and is accessible
   - Check bucket versioning is enabled (recommended)

**Findings**:
- **MEDIUM**: Browser Tool without recording enabled
- **MEDIUM**: Recording configured but S3 bucket doesn't exist
- **LOW**: S3 bucket without versioning enabled

**Resolution**: Enable session recording for audit and debugging purposes

**Reference**: https://aws.github.io/bedrock-agentcore-starter-toolkit/user-guide/browser/

### 2.7 Check: AgentCore Memory Configuration

**Function**: `check_agentcore_memory_configuration()`

**Purpose**: Validate Memory resource configuration and IAM permissions

**API Calls**:
```python
bedrock_agentcore_client.list_memories()
bedrock_agentcore_client.describe_memory(memoryId=...)
iam_client.get_role_policy(RoleName=..., PolicyName=...)
```

**Validation Logic**:
1. List all Memory resources
2. For each Memory:
   - Check IAM role has appropriate permissions:
     * bedrock-agentcore:GetMemory
     * bedrock-agentcore:UpdateMemory
     * bedrock-agentcore:DeleteMemory
   - Verify role doesn't have wildcard permissions
   - Check if encryption is configured

**Findings**:
- **HIGH**: Memory resource with overly permissive IAM role
- **MEDIUM**: Memory resource without encryption
- **N/A**: No Memory resources found (graceful handling)

**Resolution**: Apply least-privilege IAM policies and enable encryption

**Reference**: https://aws.github.io/bedrock-agentcore-starter-toolkit/user-guide/memory/

### 2.8 Check: AgentCore Gateway Configuration

**Function**: `check_agentcore_gateway_configuration()`

**Purpose**: Validate Gateway authentication and authorization configuration

**API Calls**:
```python
bedrock_agentcore_client.list_gateways()
bedrock_agentcore_client.describe_gateway(gatewayId=...)
```

**Validation Logic**:
1. List all Gateway resources
2. For each Gateway:
   - Check authentication configuration:
     * Verify authentication is enabled
     * Check authentication type (IAM, API Key, etc.)
   - Validate authorization rules exist
   - Check if rate limiting is configured

**Findings**:
- **HIGH**: Gateway without authentication enabled
- **MEDIUM**: Gateway without authorization rules
- **LOW**: Gateway without rate limiting

**Resolution**: Enable authentication, authorization, and rate limiting

**Reference**: https://aws.github.io/bedrock-agentcore-starter-toolkit/user-guide/gateway/

## 3. Data Models

### 3.1 Pydantic Schema (Reused from Existing)

The assessment reuses the existing Pydantic schema from `bedrock_assessments/schema.py`:

```python
from schema import create_finding, Finding, SeverityEnum, StatusEnum

# Example usage in checks:
finding = create_finding(
    finding_name="AgentCore VPC Configuration Check",
    finding_details="Runtime 'my-runtime' is not configured with VPC",
    resolution="Configure VPC with private subnets and required endpoints",
    reference="https://aws.github.io/bedrock-agentcore-starter-toolkit/user-guide/security/agentcore-vpc.md",
    severity='High',
    status='Failed'
)
```

### 3.2 CSV Output Format

**Columns**: Finding, Finding_Details, Resolution, Reference, Severity, Status

**Example Row**:
```csv
Finding,Finding_Details,Resolution,Reference,Severity,Status
"AgentCore VPC Configuration Check","Runtime 'my-runtime' is not configured with VPC","Configure VPC with private subnets and required endpoints","https://aws.github.io/bedrock-agentcore-starter-toolkit/user-guide/security/agentcore-vpc.md","High","Failed"
```

### 3.3 S3 Output Location

**Bucket**: `${AIML_ASSESSMENT_BUCKET_NAME}` (from environment variable)
**Key**: `agentcore_security_report_{execution_id}.csv`
**Content-Type**: `text/csv`
**Encryption**: Server-side encryption (S3 managed)



## 4. Error Handling Strategy

### 4.1 Graceful Degradation

**Principle**: Assessment should complete successfully even if some checks fail

**Implementation**:
```python
def lambda_handler(event, context):
    all_findings = []
    
    try:
        # Each check wrapped in try-except
        try:
            findings = check_agentcore_vpc_configuration()
            all_findings.append(findings)
        except Exception as e:
            logger.error(f"VPC check failed: {str(e)}")
            all_findings.append({
                'check_name': 'AgentCore VPC Configuration',
                'status': 'ERROR',
                'csv_data': [create_finding(
                    finding_name='AgentCore VPC Configuration Check',
                    finding_details=f'Error during check: {str(e)}',
                    resolution='Investigate error and retry',
                    reference='https://aws.github.io/bedrock-agentcore-starter-toolkit/',
                    severity='High',
                    status='Failed'
                )]
            })
        
        # Continue with other checks...
        
    except Exception as e:
        logger.error(f"Fatal error: {str(e)}")
        return {'statusCode': 500, 'body': str(e)}
```

### 4.2 API Error Handling

**Common Errors**:

1. **ResourceNotFoundException**: No AgentCore resources exist
   - Return N/A finding
   - Continue with assessment

2. **ThrottlingException**: API rate limit exceeded
   - Implement exponential backoff
   - Retry up to 5 times
   - Use boto3 adaptive retry mode

3. **AccessDeniedException**: Insufficient IAM permissions
   - Log error with specific permission needed
   - Return HIGH severity finding about missing permissions

4. **ServiceUnavailableException**: AgentCore service unavailable
   - Log error
   - Return ERROR status
   - Include retry recommendation

**Implementation**:
```python
from botocore.config import Config
from botocore.exceptions import ClientError

boto3_config = Config(
    retries=dict(
        max_attempts=10,
        mode='adaptive'
    )
)

def handle_api_call(func, *args, **kwargs):
    """Wrapper for API calls with error handling"""
    try:
        return func(*args, **kwargs)
    except ClientError as e:
        error_code = e.response['Error']['Code']
        
        if error_code == 'ResourceNotFoundException':
            logger.info("No resources found")
            return None
        elif error_code == 'AccessDeniedException':
            logger.error(f"Access denied: {e}")
            raise
        elif error_code == 'ThrottlingException':
            logger.warning("Throttled, retrying...")
            raise  # Let boto3 retry handle it
        else:
            logger.error(f"Unexpected error: {e}")
            raise
```

### 4.3 Timeout Handling

**Lambda Timeout**: 10 minutes (600 seconds)

**Strategy**:
- Each check should complete in < 1 minute
- Use pagination for list operations
- Limit batch sizes to avoid memory issues
- Monitor execution time and log warnings at 8 minutes

**Implementation**:
```python
import time

start_time = time.time()

def check_timeout():
    elapsed = time.time() - start_time
    if elapsed > 480:  # 8 minutes
        logger.warning(f"Approaching timeout: {elapsed}s elapsed")
    return elapsed < 540  # 9 minutes hard stop

# In each check:
if not check_timeout():
    logger.error("Timeout approaching, skipping remaining checks")
    break
```

## 5. IAM Permissions Required

### 5.1 Lambda Execution Role Permissions

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "bedrock-agentcore:ListRuntimes",
        "bedrock-agentcore:DescribeRuntime",
        "bedrock-agentcore:ListCodeInterpreters",
        "bedrock-agentcore:DescribeCodeInterpreter",
        "bedrock-agentcore:ListBrowserTools",
        "bedrock-agentcore:DescribeBrowserTool",
        "bedrock-agentcore:ListMemories",
        "bedrock-agentcore:DescribeMemory",
        "bedrock-agentcore:ListGateways",
        "bedrock-agentcore:DescribeGateway"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeSubnets",
        "ec2:DescribeRouteTables",
        "ec2:DescribeVpcEndpoints",
        "ec2:DescribeNatGateways"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "ecr:DescribeRepositories",
        "ecr:GetRepositoryPolicy"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "xray:GetTraceSummaries"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "cloudwatch:ListMetrics"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject"
      ],
      "Resource": "arn:aws:s3:::${AIML_ASSESSMENT_BUCKET_NAME}/*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:ListBucket",
        "s3:GetBucketEncryption",
        "s3:GetBucketVersioning",
        "s3:GetBucketTagging"
      ],
      "Resource": "arn:aws:s3:::*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "iam:GenerateServiceLastAccessedDetails",
        "iam:GetServiceLastAccessedDetails"
      ],
      "Resource": "*"
    }
  ]
}
```

### 5.2 Service-Linked Role

When VPC is configured, AgentCore automatically creates:
- **Role**: `AWSServiceRoleForBedrockAgentCoreNetwork`
- **Purpose**: Manage ENIs in customer VPC
- **Check**: Verify this role exists when VPC configuration is detected



## 6. Integration Points

### 6.1 Step Functions State Machine Integration

**File**: `resco-aiml-assessment/statemachine/resco_assessments.asl.json`

**Changes Required**:
1. Add third parallel branch for AgentCore assessment
2. Add function ARN substitution for AgentCoreSecurityAssessmentFunction

**Updated Parallel State**:
```json
{
  "Type": "Parallel",
  "Branches": [
    {
      "StartAt": "BedrockSecurityAssessment",
      "States": {
        "BedrockSecurityAssessment": {
          "Type": "Task",
          "Resource": "${BedrockSecurityAssessmentFunctionArn}",
          "End": true
        }
      }
    },
    {
      "StartAt": "SageMakerSecurityAssessment",
      "States": {
        "SageMakerSecurityAssessment": {
          "Type": "Task",
          "Resource": "${SageMakerSecurityAssessmentFunctionArn}",
          "End": true
        }
      }
    },
    {
      "StartAt": "AgentCoreSecurityAssessment",
      "States": {
        "AgentCoreSecurityAssessment": {
          "Type": "Task",
          "Resource": "${AgentCoreSecurityAssessmentFunctionArn}",
          "End": true
        }
      }
    }
  ],
  "Next": "GenerateConsolidatedReport"
}
```

### 6.2 SAM Template Integration

**File**: `resco-aiml-assessment/template.yaml`

**New Lambda Function Resource**:
```yaml
AgentCoreSecurityAssessmentFunction:
  Type: AWS::Serverless::Function
  Properties:
    CodeUri: functions/security/agentcore_assessments/
    Handler: app.lambda_handler
    Runtime: python3.12
    Timeout: 600
    MemorySize: 1024
    Environment:
      Variables:
        AIML_ASSESSMENT_BUCKET_NAME: !Ref AIMLAssessmentBucket
    Policies:
      - S3ReadPolicy:
          BucketName: !Ref AIMLAssessmentBucket
      - S3WritePolicy:
          BucketName: !Ref AIMLAssessmentBucket
      - Statement:
          - Effect: Allow
            Action:
              - bedrock-agentcore:ListRuntimes
              - bedrock-agentcore:DescribeRuntime
              - bedrock-agentcore:ListCodeInterpreters
              - bedrock-agentcore:DescribeCodeInterpreter
              - bedrock-agentcore:ListBrowserTools
              - bedrock-agentcore:DescribeBrowserTool
              - bedrock-agentcore:ListMemories
              - bedrock-agentcore:DescribeMemory
              - bedrock-agentcore:ListGateways
              - bedrock-agentcore:DescribeGateway
            Resource: '*'
          - Effect: Allow
            Action:
              - ec2:DescribeSubnets
              - ec2:DescribeRouteTables
              - ec2:DescribeVpcEndpoints
              - ec2:DescribeNatGateways
            Resource: '*'
          - Effect: Allow
            Action:
              - ecr:DescribeRepositories
              - ecr:GetRepositoryPolicy
            Resource: '*'
          - Effect: Allow
            Action:
              - logs:DescribeLogGroups
              - logs:DescribeLogStreams
            Resource: '*'
          - Effect: Allow
            Action:
              - xray:GetTraceSummaries
            Resource: '*'
          - Effect: Allow
            Action:
              - cloudwatch:ListMetrics
            Resource: '*'
          - Effect: Allow
            Action:
              - s3:ListBucket
              - s3:GetBucketEncryption
              - s3:GetBucketVersioning
              - s3:GetBucketTagging
            Resource: 'arn:aws:s3:::*'
          - Effect: Allow
            Action:
              - iam:GenerateServiceLastAccessedDetails
              - iam:GetServiceLastAccessedDetails
            Resource: '*'
```

**State Machine Definition Update**:
```yaml
ReSCOStateMachine:
  Type: AWS::Serverless::StateMachine
  Properties:
    DefinitionUri: statemachine/resco_assessments.asl.json
    DefinitionSubstitutions:
      BedrockSecurityAssessmentFunctionArn: !GetAtt BedrockSecurityAssessmentFunction.Arn
      SageMakerSecurityAssessmentFunctionArn: !GetAtt SageMakerSecurityAssessmentFunction.Arn
      AgentCoreSecurityAssessmentFunctionArn: !GetAtt AgentCoreSecurityAssessmentFunction.Arn
      GenerateConsolidatedReportFunctionArn: !GetAtt GenerateConsolidatedReportFunction.Arn
      IAMPermissionCachingFunctionArn: !GetAtt IAMPermissionCachingFunction.Arn
      CleanupBucketFunctionArn: !GetAtt CleanupBucketFunction.Arn
```

### 6.3 Report Generator Integration

**File**: `resco-aiml-assessment/functions/security/generate_consolidated_report/app.py`

**Changes Required**:
1. Add logic to read `agentcore_security_report_{execution_id}.csv` files
2. Add 'agentcore' category to assessment_results dictionary
3. Update HTML template to display AgentCore findings

**Code Changes**:
```python
# In lambda_handler function, add:
agentcore_files = [f for f in csv_files if f.startswith('agentcore_security_report_')]

for file_key in agentcore_files:
    try:
        obj = s3_client.get_object(Bucket=bucket_name, Key=file_key)
        content = obj['Body'].read().decode('utf-8')
        reader = csv.DictReader(StringIO(content))
        
        for row in reader:
            assessment_results['agentcore'].append({
                'finding': row['Finding'],
                'details': row['Finding_Details'],
                'resolution': row['Resolution'],
                'reference': row['Reference'],
                'severity': row['Severity'],
                'status': row['Status']
            })
    except Exception as e:
        logger.error(f"Error processing AgentCore file {file_key}: {str(e)}")
```

## 7. Testing Strategy

### 7.1 Unit Testing

**Test File**: `resco-aiml-assessment/functions/security/agentcore_assessments/test_app.py`

**Test Cases**:
1. `test_check_agentcore_vpc_configuration_no_resources()`
   - Mock empty list_runtimes response
   - Verify N/A finding returned

2. `test_check_agentcore_vpc_configuration_missing_vpc()`
   - Mock runtime without vpcConfig
   - Verify HIGH severity finding

3. `test_check_agentcore_full_access_roles()`
   - Mock permission_cache with full access role
   - Verify HIGH severity finding

4. `test_check_stale_agentcore_access()`
   - Mock IAM last accessed data > 60 days
   - Verify MEDIUM severity finding

5. `test_check_agentcore_observability_missing_logs()`
   - Mock runtime without logging config
   - Verify MEDIUM severity finding

6. `test_check_agentcore_encryption_missing()`
   - Mock ECR repo without encryption
   - Verify HIGH severity finding

7. `test_lambda_handler_success()`
   - Mock all checks returning findings
   - Verify CSV generated and uploaded to S3

8. `test_lambda_handler_permission_cache_missing()`
   - Mock missing permission cache
   - Verify graceful handling with empty cache

### 7.2 Integration Testing

**Prerequisites**:
- AWS account with AgentCore resources deployed
- IAM permissions for Lambda execution role
- S3 bucket for results

**Test Scenarios**:
1. **Full Assessment Run**
   - Deploy Lambda function
   - Trigger with test event
   - Verify CSV report generated
   - Validate findings accuracy

2. **No Resources Scenario**
   - Run in account without AgentCore resources
   - Verify N/A findings returned
   - Verify no errors thrown

3. **Partial Resources Scenario**
   - Deploy only Runtime (no Code Interpreter/Browser)
   - Verify assessment handles gracefully
   - Verify findings only for existing resources

4. **API Throttling Scenario**
   - Simulate high API call volume
   - Verify exponential backoff works
   - Verify assessment completes successfully

### 7.3 End-to-End Testing

**Test Workflow**:
1. Deploy complete SAM stack
2. Trigger Step Functions execution
3. Verify all three assessments run in parallel
4. Verify consolidated report includes AgentCore findings
5. Validate HTML report displays correctly

**Validation Criteria**:
- All 8 AgentCore checks execute
- Findings match expected security posture
- CSV report uploaded to S3
- Consolidated HTML report includes AgentCore section
- No errors in CloudWatch Logs



## 8. Performance Considerations

### 8.1 API Call Optimization

**Pagination Strategy**:
```python
def list_all_runtimes(client):
    """List all runtimes with pagination"""
    runtimes = []
    paginator = client.get_paginator('list_runtimes')
    
    for page in paginator.paginate():
        runtimes.extend(page.get('runtimes', []))
    
    return runtimes
```

**Batch Processing**:
- Process resources in batches of 10
- Use concurrent API calls where possible (within rate limits)
- Cache repeated lookups (e.g., VPC endpoint checks)

**Rate Limiting**:
- Respect AWS API rate limits
- Use boto3 adaptive retry mode
- Add jitter to avoid thundering herd

### 8.2 Memory Management

**Expected Memory Usage**:
- Base Lambda overhead: ~100 MB
- Boto3 clients: ~50 MB
- Permission cache: ~10-50 MB (depending on account size)
- Assessment data: ~10-20 MB
- Peak usage: ~200-300 MB

**Optimization**:
- Stream CSV generation instead of building in memory
- Process findings incrementally
- Clear large objects after use

### 8.3 Execution Time Estimates

**Per-Check Timing** (typical account with 10 resources):
- VPC Configuration: 30-60 seconds
- IAM Full Access: 5-10 seconds (cached)
- Stale Access: 60-90 seconds (IAM API latency)
- Observability: 20-30 seconds
- Encryption: 30-45 seconds
- Browser Recording: 15-20 seconds
- Memory Configuration: 10-15 seconds
- Gateway Configuration: 10-15 seconds

**Total Estimated Time**: 3-5 minutes for typical account

**Worst Case** (100+ resources): 8-9 minutes

## 9. Monitoring and Observability

### 9.1 CloudWatch Metrics

**Custom Metrics to Publish**:
```python
cloudwatch = boto3.client('cloudwatch')

cloudwatch.put_metric_data(
    Namespace='ReSCO/AgentCore',
    MetricData=[
        {
            'MetricName': 'AssessmentDuration',
            'Value': execution_time,
            'Unit': 'Seconds'
        },
        {
            'MetricName': 'FindingsCount',
            'Value': len(all_findings),
            'Unit': 'Count',
            'Dimensions': [
                {'Name': 'Severity', 'Value': 'High'}
            ]
        },
        {
            'MetricName': 'ResourcesScanned',
            'Value': total_resources,
            'Unit': 'Count'
        }
    ]
)
```

### 9.2 CloudWatch Logs

**Log Levels**:
- ERROR: API failures, permission issues, unexpected errors
- WARNING: Throttling, missing resources, degraded checks
- INFO: Check start/completion, resource counts
- DEBUG: Detailed API responses (disabled in production)

**Structured Logging**:
```python
logger.info(json.dumps({
    'event': 'check_completed',
    'check_name': 'vpc_configuration',
    'duration_ms': duration,
    'findings_count': len(findings),
    'status': 'success'
}))
```

### 9.3 X-Ray Tracing

**Instrumentation**:
```python
from aws_xray_sdk.core import xray_recorder
from aws_xray_sdk.core import patch_all

patch_all()

@xray_recorder.capture('check_agentcore_vpc_configuration')
def check_agentcore_vpc_configuration():
    # Function implementation
    pass
```

**Segments to Track**:
- Each assessment check
- S3 upload operation
- Permission cache retrieval
- API calls to bedrock-agentcore-control

## 10. Security Considerations

### 10.1 Least Privilege Access

**Lambda Execution Role**:
- Read-only access to AgentCore APIs
- No write permissions to AgentCore resources
- Scoped S3 access to assessment bucket only
- No access to customer data or sensitive resources

### 10.2 Data Protection

**Sensitive Data Handling**:
- No PII in CloudWatch Logs
- Resource IDs and ARNs only (no names with PII)
- Sanitize error messages before logging
- Encrypt S3 results with SSE-S3

**Example Sanitization**:
```python
def sanitize_resource_name(name):
    """Remove potential PII from resource names"""
    # Keep only alphanumeric and hyphens
    return re.sub(r'[^a-zA-Z0-9-]', 'X', name)
```

### 10.3 Audit Trail

**CloudTrail Integration**:
- All API calls logged to CloudTrail
- Assessment execution tracked in Step Functions
- S3 access logged with bucket logging
- IAM permission checks logged

## 11. Deployment Considerations

### 11.1 Prerequisites

**Required**:
- AWS SAM CLI installed
- Python 3.12 runtime available
- S3 bucket for SAM artifacts
- IAM permissions to create Lambda functions

**Optional**:
- AgentCore resources deployed (for testing)
- VPC configuration (if testing VPC checks)

### 11.2 Deployment Steps

```bash
# 1. Build SAM application
sam build

# 2. Deploy to AWS
sam deploy --guided

# 3. Test Lambda function
aws lambda invoke \
  --function-name AgentCoreSecurityAssessmentFunction \
  --payload '{"Execution":{"Name":"test-123"}}' \
  response.json

# 4. Verify S3 output
aws s3 ls s3://${BUCKET_NAME}/agentcore_security_report_test-123.csv
```

### 11.3 Rollback Strategy

**If Deployment Fails**:
1. Check CloudFormation stack events
2. Review Lambda function logs
3. Verify IAM permissions
4. Rollback to previous stack version

**If Assessment Fails**:
1. Check CloudWatch Logs for errors
2. Verify permission cache exists
3. Test individual checks manually
4. Disable problematic checks temporarily

## 12. Future Enhancements

### 12.1 Planned Features

1. **Multi-Account Support**
   - Cross-account role assumption
   - Aggregated reporting across accounts
   - Organization-wide compliance dashboard

2. **Custom Security Policies**
   - User-defined security rules
   - Configurable severity levels
   - Custom remediation guidance

3. **Automated Remediation**
   - Auto-enable VPC configuration
   - Auto-configure observability
   - Auto-apply least-privilege policies

4. **Real-Time Monitoring**
   - EventBridge integration for resource changes
   - Continuous compliance checking
   - Slack/SNS notifications for critical findings

### 12.2 API Evolution

**Handling API Changes**:
- Version detection for bedrock-agentcore-control API
- Graceful degradation for deprecated APIs
- Feature flags for new API capabilities

**Backward Compatibility**:
- Support multiple API versions
- Fallback to older API calls if new ones fail
- Version-specific error handling

## 13. Documentation References

### 13.1 AWS Documentation

- [Amazon Bedrock AgentCore Documentation](https://aws.github.io/bedrock-agentcore-starter-toolkit/)
- [AgentCore VPC Configuration](https://aws.github.io/bedrock-agentcore-starter-toolkit/user-guide/security/agentcore-vpc.md)
- [AgentCore Runtime Permissions](https://aws.github.io/bedrock-agentcore-starter-toolkit/user-guide/runtime/permissions.md)
- [AgentCore Observability](https://aws.github.io/bedrock-agentcore-starter-toolkit/user-guide/observability/)
- [AWS Well-Architected Framework - Generative AI Lens](https://docs.aws.amazon.com/wellarchitected/latest/generative-ai-lens/)

### 13.2 Internal References

- Bedrock Assessment: `resco-aiml-assessment/functions/security/bedrock_assessments/app.py`
- SageMaker Assessment: `resco-aiml-assessment/functions/security/sagemaker_assessments/app.py`
- Schema Definition: `resco-aiml-assessment/functions/security/bedrock_assessments/schema.py`
- Requirements Document: `.kiro/specs/agentcore-security-assessment/requirements.md`

## 14. Appendix

### 14.1 Severity Level Guidelines

**HIGH**:
- Missing VPC configuration (public internet exposure)
- Full access IAM policies
- Missing encryption
- Missing authentication

**MEDIUM**:
- Stale access (60+ days)
- Missing observability
- Missing authorization rules
- Missing recording configuration

**LOW**:
- AWS-managed keys vs customer-managed
- Missing rate limiting
- Missing versioning
- Informational recommendations

**N/A**:
- No resources found
- Check not applicable
- Feature not in use

### 14.2 Common Troubleshooting

**Issue**: Permission cache not found
- **Cause**: IAMPermissionCachingFunction failed
- **Solution**: Check IAM function logs, verify S3 bucket access

**Issue**: API throttling errors
- **Cause**: Too many API calls in short time
- **Solution**: Increase retry backoff, reduce batch size

**Issue**: Timeout errors
- **Cause**: Too many resources to scan
- **Solution**: Increase Lambda timeout, optimize pagination

**Issue**: Missing findings in report
- **Cause**: Check failed silently
- **Solution**: Review CloudWatch Logs, enable DEBUG logging

### 14.3 Glossary

- **AgentCore Runtime**: Serverless execution environment for agents
- **Code Interpreter**: Sandboxed Python execution environment
- **Browser Tool**: Headless browser for web interaction
- **Memory**: Persistent knowledge storage for agents
- **Gateway**: API gateway for agent tool integration
- **VPC Endpoint**: Private connection to AWS services
- **Permission Boundary**: Maximum permissions for IAM entity
- **Service-Linked Role**: AWS-managed role for service operations

---

**Document Version**: 1.0
**Last Updated**: 2026-01-29
**Author**: Kiro AI Assistant
**Status**: Ready for Implementation
