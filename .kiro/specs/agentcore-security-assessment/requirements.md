# Amazon Bedrock AgentCore Security Assessment - Requirements

## Overview
Add comprehensive security assessments for Amazon Bedrock AgentCore to the ReSCO AI/ML assessment framework, following the same patterns as existing Bedrock and SageMaker assessments.

## User Stories

### US-1: As a security engineer, I want to assess AgentCore VPC configurations
**Acceptance Criteria:**
- AC-1.1: System detects AgentCore Runtimes without VPC configuration
- AC-1.2: System detects Code Interpreters without VPC configuration
- AC-1.3: System detects Browser Tools without VPC configuration
- AC-1.4: System validates required VPC endpoints exist (ECR, S3, CloudWatch Logs) when VPC is configured
- AC-1.5: System checks if resources are in private subnets (not public)
- AC-1.6: System validates NAT gateway configuration for internet access
- AC-1.7: System reports findings with High severity for missing VPC configuration

### US-2: As a security engineer, I want to identify overly permissive IAM access to AgentCore
**Acceptance Criteria:**
- AC-2.1: System detects roles with BedrockAgentCoreFullAccess managed policy
- AC-2.2: System validates runtime execution roles follow least privilege principles
- AC-2.3: System checks for service-linked role AWSServiceRoleForBedrockAgentCoreNetwork when VPC is used
- AC-2.4: System identifies IAM principals with AgentCore permissions but no usage in 60+ days
- AC-2.5: System reports full access policies with High severity
- AC-2.6: System reports stale access with Medium severity

### US-3: As a security engineer, I want to verify AgentCore observability is configured
**Acceptance Criteria:**
- AC-3.1: System checks if CloudWatch Logs are enabled for runtimes
- AC-3.2: System verifies X-Ray tracing is configured
- AC-3.3: System validates CloudWatch custom metrics are being published
- AC-3.4: System reports missing observability with Medium severity

### US-4: As a security engineer, I want to ensure AgentCore resources have proper encryption
**Acceptance Criteria:**
- AC-4.1: System checks ECR repositories for encryption configuration
- AC-4.2: System validates S3 buckets used for Browser Tool recordings have encryption enabled
- AC-4.3: System reports missing encryption with High severity
- AC-4.4: System reports AWS-managed keys vs customer-managed keys with Low severity

### US-5: As a security engineer, I want to verify Browser Tool security configurations
**Acceptance Criteria:**
- AC-5.1: System checks if Browser Tool session recording is enabled
- AC-5.2: System validates recording S3 bucket configuration
- AC-5.3: System reports missing recording with Medium severity

### US-6: As a security engineer, I want AgentCore assessments to integrate seamlessly with existing workflow
**Acceptance Criteria:**
- AC-6.1: AgentCore assessment runs in parallel with Bedrock and SageMaker assessments
- AC-6.2: Assessment results are written to CSV with same schema as other assessments
- AC-6.3: Assessment results appear in consolidated HTML report
- AC-6.4: Assessment runs gracefully when no AgentCore resources exist (returns "N/A" findings)
- AC-6.5: Assessment uses cached IAM permissions from IAMPermissionCachingFunction
- AC-6.6: Assessment completes within 10 minutes timeout

### US-7: As a security engineer, I want to assess AgentCore Memory and Gateway configurations
**Acceptance Criteria:**
- AC-7.1: System lists all AgentCore Memory resources
- AC-7.2: System lists all AgentCore Gateway resources
- AC-7.3: System validates Memory resource IAM permissions
- AC-7.4: System validates Gateway authentication configurations
- AC-7.5: System reports findings with appropriate severity levels

## Functional Requirements

### FR-1: Lambda Function Implementation
- FR-1.1: Create new Lambda function `AgentCoreSecurityAssessmentFunction`
- FR-1.2: Function must use Python 3.12 runtime
- FR-1.3: Function must have 10-minute timeout
- FR-1.4: Function must have 1024MB memory allocation
- FR-1.5: Function must use boto3 with adaptive retry configuration

### FR-2: AWS API Integration
- FR-2.1: Use `bedrock-agentcore-control` client for AgentCore APIs
- FR-2.2: Implement pagination for list operations
- FR-2.3: Handle API throttling with exponential backoff
- FR-2.4: Handle service unavailability gracefully

### FR-3: Assessment Checks
- FR-3.1: Implement `check_agentcore_vpc_configuration()`
- FR-3.2: Implement `check_agentcore_iam_permissions(permission_cache)`
- FR-3.3: Implement `check_agentcore_observability()`
- FR-3.4: Implement `check_agentcore_full_access_roles(permission_cache)`
- FR-3.5: Implement `check_stale_agentcore_access(permission_cache)`
- FR-3.6: Implement `check_agentcore_encryption()`
- FR-3.7: Implement `check_browser_tool_recording()`
- FR-3.8: Implement `check_agentcore_memory_gateway()`

### FR-4: Output Format
- FR-4.1: Generate CSV file with columns: Finding, Finding_Details, Resolution, Reference, Severity, Status
- FR-4.2: Use Pydantic schema validation for all findings
- FR-4.3: Write CSV to S3 with naming pattern: `agentcore_security_report_{execution_id}.csv`
- FR-4.4: Include AWS documentation references for all findings

### FR-5: IAM Permissions
- FR-5.1: Lambda requires read-only access to bedrock-agentcore-control APIs
- FR-5.2: Lambda requires EC2 describe permissions for VPC validation
- FR-5.3: Lambda requires ECR describe permissions for encryption checks
- FR-5.4: Lambda requires CloudWatch Logs describe permissions
- FR-5.5: Lambda requires S3 read/write for results storage

## Non-Functional Requirements

### NFR-1: Performance
- NFR-1.1: Assessment must complete within 10 minutes
- NFR-1.2: Assessment must handle accounts with 100+ AgentCore resources
- NFR-1.3: API calls must use pagination to avoid memory issues

### NFR-2: Reliability
- NFR-2.1: Assessment must handle API errors gracefully
- NFR-2.2: Assessment must continue if one check fails
- NFR-2.3: Assessment must log errors to CloudWatch

### NFR-3: Maintainability
- NFR-3.1: Code must follow existing patterns from Bedrock/SageMaker assessments
- NFR-3.2: Functions must have docstrings with type hints
- NFR-3.3: Error handling must be consistent across all checks

### NFR-4: Compatibility
- NFR-4.1: Must work with existing Step Functions workflow
- NFR-4.2: Must integrate with existing report generation
- NFR-4.3: Must use existing schema validation (Pydantic)
- NFR-4.4: Must work in single-account mode

## Technical Constraints

### TC-1: AWS Service Availability
- TC-1.1: bedrock-agentcore-control API must be available in deployment region
- TC-1.2: Assessment must handle regions where AgentCore is not available

### TC-2: Backward Compatibility
- TC-2.1: Existing Bedrock and SageMaker assessments must continue to work
- TC-2.2: Consolidated report generation must handle AgentCore results
- TC-2.3: Step Functions state machine must support new parallel branch

### TC-3: Security
- TC-3.1: Lambda must use least-privilege IAM permissions
- TC-3.2: No sensitive data in CloudWatch logs
- TC-3.3: S3 results must use server-side encryption

## Out of Scope

### OS-1: Multi-Account Support
- Multi-account AgentCore assessments will be added in a future iteration

### OS-2: Real-Time Monitoring
- Continuous monitoring of AgentCore resources is not included

### OS-3: Automated Remediation
- Automatic fixing of identified issues is not included

### OS-4: Custom Policies
- User-defined custom security checks are not included

## Dependencies

### D-1: Existing Components
- IAMPermissionCachingFunction must run before AgentCore assessment
- CleanupBucketFunction must run before all assessments
- GenerateConsolidatedReportFunction must support AgentCore results

### D-2: AWS Services
- Amazon Bedrock AgentCore Control Plane API
- AWS IAM for permission checks
- Amazon EC2 for VPC validation
- Amazon ECR for encryption checks
- Amazon CloudWatch Logs for observability checks
- Amazon S3 for results storage

### D-3: Python Libraries
- boto3 >= 1.34.0 (for AgentCore API support)
- pydantic >= 2.0
- typing-extensions

## Success Metrics

### SM-1: Functional Completeness
- All 8 assessment checks implemented and tested
- All acceptance criteria met
- Zero critical bugs in production

### SM-2: Performance
- Assessment completes in < 5 minutes for typical accounts
- No API throttling errors under normal load
- Memory usage stays under 512MB

### SM-3: Quality
- Code coverage > 80% for new functions
- All findings include valid AWS documentation references
- Pydantic validation passes for all findings

## References

- [Amazon Bedrock AgentCore Documentation](https://aws.github.io/bedrock-agentcore-starter-toolkit/)
- [AgentCore VPC Configuration](https://aws.github.io/bedrock-agentcore-starter-toolkit/user-guide/security/agentcore-vpc.md)
- [AgentCore Runtime Permissions](https://aws.github.io/bedrock-agentcore-starter-toolkit/user-guide/runtime/permissions.md)
- Existing Bedrock assessment: `resco-aiml-assessment/functions/security/bedrock_assessments/app.py`
- Existing SageMaker assessment: `resco-aiml-assessment/functions/security/sagemaker_assessments/app.py`
