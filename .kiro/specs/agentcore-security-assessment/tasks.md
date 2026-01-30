# Amazon Bedrock AgentCore Security Assessment - Implementation Tasks

## Task Status Legend
- `[ ]` Not started
- `[~]` Queued
- `[-]` In progress
- `[x]` Completed

## 1. Lambda Function Implementation

### 1.1 Create Project Structure
- [x] 1.1.1 Create directory `resco-aiml-assessment/functions/security/agentcore_assessments/`
- [x] 1.1.2 Create `__init__.py` file
- [x] 1.1.3 Create `requirements.txt` with dependencies (boto3>=1.34.0, pydantic>=2.0, typing-extensions)
- [x] 1.1.4 Copy `schema.py` from bedrock_assessments (reuse existing Pydantic models)

### 1.2 Implement Core Infrastructure
- [x] 1.2.1 Create `app.py` with imports and boto3 configuration
  - Import required libraries (boto3, csv, logging, datetime, etc.)
  - Configure boto3 with adaptive retry mode
  - Set up logging configuration
- [x] 1.2.2 Implement `get_permissions_cache(execution_id)` function
  - Retrieve permissions cache JSON from S3
  - Parse and return as dictionary
  - Handle missing cache gracefully
- [x] 1.2.3 Implement `get_current_utc_date()` helper function
- [x] 1.2.4 Implement `generate_csv_report(findings)` function
  - Create CSV with required columns
  - Use StringIO for in-memory generation
  - Validate findings with Pydantic schema
- [x] 1.2.5 Implement `write_to_s3(execution_id, csv_content, bucket_name)` function
  - Upload CSV to S3 with naming pattern
  - Return S3 URL
  - Handle upload errors

### 1.3 Implement Assessment Check Functions

#### 1.3.1 VPC Configuration Check
- [x] 1.3.1.1 Implement `check_agentcore_vpc_configuration()` function
  - List all AgentCore Runtimes
  - Check for VPC configuration
  - Validate subnet configuration (private vs public)
  - Check for required VPC endpoints (ECR, S3, CloudWatch Logs)
  - Validate NAT gateway configuration
  - Repeat for Code Interpreters
  - Repeat for Browser Tools
  - Generate findings with appropriate severity
  - Handle ResourceNotFoundException gracefully

#### 1.3.2 IAM Full Access Check
- [x] 1.3.2.1 Implement `check_agentcore_full_access_roles(permission_cache)` function
  - Iterate through role_permissions in cache
  - Check for BedrockAgentCoreFullAccess policy
  - Check for custom policies with wildcard AgentCore permissions
  - Generate HIGH severity findings for full access
  - Return N/A if no issues found

#### 1.3.3 Stale Access Check
- [x] 1.3.3.1 Implement `check_stale_agentcore_access(permission_cache)` function
  - Identify roles/users with AgentCore permissions
  - Generate service last accessed details for each principal
  - Wait for job completion (max 30 seconds)
  - Check last access to "Amazon Bedrock AgentCore"
  - Flag if last_accessed > 60 days or never accessed
  - Generate MEDIUM severity findings
  - Handle API errors gracefully

#### 1.3.4 Observability Check
- [x] 1.3.4.1 Implement `check_agentcore_observability()` function
  - List all AgentCore Runtimes
  - Check CloudWatch Logs configuration
  - Verify log groups exist and are active
  - Check X-Ray tracing configuration
  - Verify CloudWatch custom metrics are published
  - Generate MEDIUM severity findings for missing observability
  - Return N/A if no resources found

#### 1.3.5 Encryption Check
- [x] 1.3.5.1 Implement `check_agentcore_encryption()` function
  - Identify ECR repositories used by AgentCore (via tags)
  - Check ECR encryption configuration
  - Identify S3 buckets for Browser Tool recordings (via tags)
  - Check S3 bucket encryption configuration
  - Differentiate AWS-managed vs customer-managed keys
  - Generate HIGH severity for missing encryption
  - Generate LOW severity for AWS-managed keys

#### 1.3.6 Browser Tool Recording Check
- [x] 1.3.6.1 Implement `check_browser_tool_recording()` function
  - List all Browser Tools
  - Check if recording is enabled
  - Verify S3 bucket configuration
  - Check bucket exists and is accessible
  - Verify bucket versioning (recommended)
  - Generate MEDIUM severity findings
  - Handle no Browser Tools gracefully

#### 1.3.7 Memory Configuration Check
- [x] 1.3.7.1 Implement `check_agentcore_memory_configuration()` function
  - List all Memory resources
  - Check IAM role permissions for each Memory
  - Verify least-privilege access
  - Check encryption configuration
  - Generate HIGH severity for overly permissive roles
  - Return N/A if no Memory resources

#### 1.3.8 Gateway Configuration Check
- [x] 1.3.8.1 Implement `check_agentcore_gateway_configuration()` function
  - List all Gateway resources
  - Check authentication configuration
  - Validate authorization rules exist
  - Check rate limiting configuration
  - Generate HIGH severity for missing authentication
  - Return N/A if no Gateway resources

### 1.4 Implement Lambda Handler
- [x] 1.4.1 Implement `lambda_handler(event, context)` function
  - Extract execution_id from event
  - Retrieve permission cache
  - Execute all 8 assessment checks in sequence
  - Collect findings from each check
  - Handle individual check failures gracefully
  - Generate CSV report
  - Upload to S3
  - Return success/failure response
  - Log execution metrics

### 1.5 Error Handling and Logging
- [ ] 1.5.1 Add comprehensive error handling to all functions
  - Wrap each check in try-except
  - Log errors with context
  - Continue assessment even if one check fails
- [ ] 1.5.2 Add structured logging throughout
  - Log check start/completion
  - Log resource counts
  - Log API errors
  - Log execution time
- [ ] 1.5.3 Implement timeout monitoring
  - Track execution time
  - Log warnings at 8 minutes
  - Stop gracefully at 9 minutes



## 2. SAM Template Updates

### 2.1 Add Lambda Function Resource
- [x] 2.1.1 Open `resco-aiml-assessment/template.yaml`
- [x] 2.1.2 Add `AgentCoreSecurityAssessmentFunction` resource
  - Set CodeUri to `functions/security/agentcore_assessments/`
  - Set Handler to `app.lambda_handler`
  - Set Runtime to `python3.12`
  - Set Timeout to `600` seconds
  - Set MemorySize to `1024` MB
- [x] 2.1.3 Add environment variables
  - AIML_ASSESSMENT_BUCKET_NAME: !Ref AIMLAssessmentBucket
- [x] 2.1.4 Add IAM policies
  - S3ReadPolicy for assessment bucket
  - S3WritePolicy for assessment bucket
  - bedrock-agentcore:* read permissions
  - ec2:Describe* permissions for VPC validation
  - ecr:Describe* permissions for encryption checks
  - logs:Describe* permissions for observability
  - xray:GetTraceSummaries permission
  - cloudwatch:ListMetrics permission
  - s3:ListBucket, s3:GetBucket* for bucket checks
  - iam:GenerateServiceLastAccessedDetails permission
  - iam:GetServiceLastAccessedDetails permission

### 2.2 Update State Machine Definition
- [x] 2.2.1 Add AgentCoreSecurityAssessmentFunctionArn to DefinitionSubstitutions
- [ ] 2.2.2 Update state machine to reference new function ARN

## 3. Step Functions State Machine Updates

### 3.1 Update Parallel Execution
- [x] 3.1.1 Open `resco-aiml-assessment/statemachine/resco_assessments.asl.json`
- [x] 3.1.2 Add third parallel branch for AgentCore assessment
  - Add "AgentCoreSecurityAssessment" state
  - Set Type to "Task"
  - Set Resource to "${AgentCoreSecurityAssessmentFunctionArn}"
  - Set End to true
- [ ] 3.1.3 Verify parallel branches are properly configured
- [ ] 3.1.4 Test state machine definition syntax

## 4. Report Generator Updates

### 4.1 Update Consolidated Report Function
- [x] 4.1.1 Open `resco-aiml-assessment/functions/security/generate_consolidated_report/app.py`
- [x] 4.1.2 Add logic to read `agentcore_security_report_{execution_id}.csv` files
  - Filter CSV files for agentcore prefix
  - Parse CSV content
  - Handle missing files gracefully
- [x] 4.1.3 Add 'agentcore' category to assessment_results dictionary
  - Initialize empty list for agentcore findings
  - Append parsed findings to list
- [x] 4.1.4 Update HTML template to display AgentCore findings
  - Add AgentCore section to report
  - Display findings with severity colors
  - Include resolution guidance
  - Add reference links

## 5. Testing

### 5.1 Unit Tests
- [ ] 5.1.1 Create `resco-aiml-assessment/functions/security/agentcore_assessments/test_app.py`
- [ ] 5.1.2 Write test for `check_agentcore_vpc_configuration()`
  - Test with no resources (N/A finding)
  - Test with missing VPC (HIGH finding)
  - Test with proper VPC configuration (PASS)
- [ ] 5.1.3 Write test for `check_agentcore_full_access_roles()`
  - Test with full access policy (HIGH finding)
  - Test with least-privilege policy (PASS)
- [ ] 5.1.4 Write test for `check_stale_agentcore_access()`
  - Test with stale access > 60 days (MEDIUM finding)
  - Test with recent access (PASS)
- [ ] 5.1.5 Write test for `check_agentcore_observability()`
  - Test with missing logs (MEDIUM finding)
  - Test with proper observability (PASS)
- [ ] 5.1.6 Write test for `check_agentcore_encryption()`
  - Test with missing encryption (HIGH finding)
  - Test with AWS-managed keys (LOW finding)
  - Test with customer-managed keys (PASS)
- [ ] 5.1.7 Write test for `check_browser_tool_recording()`
  - Test with recording disabled (MEDIUM finding)
  - Test with recording enabled (PASS)
- [ ] 5.1.8 Write test for `check_agentcore_memory_configuration()`
  - Test with overly permissive role (HIGH finding)
  - Test with least-privilege role (PASS)
- [ ] 5.1.9 Write test for `check_agentcore_gateway_configuration()`
  - Test with missing authentication (HIGH finding)
  - Test with proper authentication (PASS)
- [ ] 5.1.10 Write test for `lambda_handler()`
  - Test successful execution
  - Test with missing permission cache
  - Test with individual check failures
- [ ] 5.1.11 Run all unit tests and verify 80%+ coverage

### 5.2 Integration Tests
- [ ] 5.2.1 Deploy Lambda function to test AWS account
- [ ] 5.2.2 Create test AgentCore resources
  - Create Runtime with VPC configuration
  - Create Memory resource
  - Configure IAM roles
- [ ] 5.2.3 Trigger Lambda function with test event
- [ ] 5.2.4 Verify CSV report generated in S3
- [ ] 5.2.5 Validate findings accuracy
- [ ] 5.2.6 Test with no AgentCore resources (N/A scenario)
- [ ] 5.2.7 Test API throttling handling
- [ ] 5.2.8 Test timeout handling (simulate long execution)

### 5.3 End-to-End Tests
- [ ] 5.3.1 Deploy complete SAM stack
- [ ] 5.3.2 Trigger Step Functions execution
- [ ] 5.3.3 Verify all three assessments run in parallel
- [ ] 5.3.4 Verify AgentCore CSV uploaded to S3
- [ ] 5.3.5 Verify consolidated HTML report includes AgentCore section
- [ ] 5.3.6 Validate report displays correctly in browser
- [ ] 5.3.7 Check CloudWatch Logs for errors
- [ ] 5.3.8 Verify X-Ray traces show all checks

## 6. Documentation Updates

### 6.1 Update Main README
- [ ] 6.1.1 Open `README.md`
- [ ] 6.1.2 Add AgentCore to list of supported services
- [ ] 6.1.3 Update architecture diagram (if applicable)
- [ ] 6.1.4 Add AgentCore-specific prerequisites
- [ ] 6.1.5 Update feature list

### 6.2 Update ReSCO README
- [ ] 6.2.1 Open `resco-aiml-assessment/README.md`
- [ ] 6.2.2 Add AgentCore assessment details
  - List 8 security checks
  - Describe findings and severity levels
  - Add example findings
- [ ] 6.2.3 Update deployment instructions
- [ ] 6.2.4 Add troubleshooting section for AgentCore
- [ ] 6.2.5 Update IAM permissions documentation

### 6.3 Create AgentCore-Specific Documentation
- [ ] 6.3.1 Create `resco-aiml-assessment/docs/agentcore-assessment.md`
- [ ] 6.3.2 Document each security check in detail
- [ ] 6.3.3 Provide remediation guidance
- [ ] 6.3.4 Add reference links to AWS documentation
- [ ] 6.3.5 Include example findings and resolutions

## 7. Deployment and Validation

### 7.1 Pre-Deployment Checklist
- [ ] 7.1.1 Verify all unit tests pass
- [ ] 7.1.2 Verify all integration tests pass
- [ ] 7.1.3 Review code for security issues
- [ ] 7.1.4 Validate IAM permissions are least-privilege
- [ ] 7.1.5 Check for hardcoded values or secrets
- [ ] 7.1.6 Verify error handling is comprehensive
- [ ] 7.1.7 Review logging for sensitive data

### 7.2 Deployment Steps
- [x] 7.2.1 Build SAM application: `sam build`
- [ ] 7.2.2 Validate SAM template: `sam validate`
- [x] 7.2.3 Deploy to test environment: `sam deploy --guided`
- [ ] 7.2.4 Run smoke tests in test environment
- [ ] 7.2.5 Deploy to production environment
- [ ] 7.2.6 Monitor CloudWatch Logs for errors
- [ ] 7.2.7 Verify first production execution succeeds

### 7.3 Post-Deployment Validation
- [x] 7.3.1 Trigger Step Functions execution
- [x] 7.3.2 Verify AgentCore assessment completes successfully
- [ ] 7.3.3 Download and review CSV report
- [x] 7.3.4 Verify consolidated HTML report includes AgentCore
- [ ] 7.3.5 Check CloudWatch metrics
- [ ] 7.3.6 Review X-Ray traces
- [ ] 7.3.7 Validate findings match expected security posture
- [ ] 7.3.8 Test with different account configurations

## 8. Monitoring and Maintenance

### 8.1 Set Up Monitoring
- [ ] 8.1.1 Create CloudWatch dashboard for AgentCore assessment
  - Add execution duration metric
  - Add findings count by severity
  - Add error rate metric
  - Add resources scanned metric
- [ ] 8.1.2 Set up CloudWatch alarms
  - Alarm for execution failures
  - Alarm for high error rate
  - Alarm for timeout warnings
- [ ] 8.1.3 Configure SNS notifications for critical alarms

### 8.2 Ongoing Maintenance
- [ ] 8.2.1 Monitor for AWS API changes
- [ ] 8.2.2 Update boto3 version regularly
- [ ] 8.2.3 Review and update security checks quarterly
- [ ] 8.2.4 Collect feedback from users
- [ ] 8.2.5 Plan future enhancements

## 9. Optional Enhancements

### 9.1 Performance Optimization
- [ ]* 9.1.1 Implement concurrent API calls where safe
- [ ]* 9.1.2 Add caching for repeated lookups
- [ ]* 9.1.3 Optimize pagination batch sizes
- [ ]* 9.1.4 Profile and optimize slow checks

### 9.2 Advanced Features
- [ ]* 9.2.1 Add custom security policy support
- [ ]* 9.2.2 Implement configurable severity levels
- [ ]* 9.2.3 Add automated remediation suggestions
- [ ]* 9.2.4 Create compliance mapping (e.g., CIS, NIST)

### 9.3 Multi-Account Support
- [ ]* 9.3.1 Design cross-account architecture
- [ ]* 9.3.2 Implement role assumption logic
- [ ]* 9.3.3 Add aggregated reporting
- [ ]* 9.3.4 Test with multiple accounts

---

## Task Summary

**Total Tasks**: 100+
**Required Tasks**: 85
**Optional Tasks**: 15

**Estimated Effort**:
- Lambda Implementation: 16-20 hours
- SAM Template Updates: 2-3 hours
- Report Generator Updates: 2-3 hours
- Testing: 8-10 hours
- Documentation: 4-5 hours
- Deployment & Validation: 3-4 hours
- **Total**: 35-45 hours

**Dependencies**:
- IAMPermissionCachingFunction must be deployed first
- Existing Bedrock/SageMaker assessments should be working
- S3 bucket for results must exist
- Test AWS account with AgentCore resources

**Success Criteria**:
- All 8 assessment checks implemented and tested
- CSV report generated with correct schema
- Consolidated HTML report includes AgentCore findings
- No errors in production execution
- Code coverage > 80%
- Documentation complete and accurate
