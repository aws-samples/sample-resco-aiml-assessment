# AI/ML Security Assessments

## Overview

This project provides a framework for performing security assessments of AI/ML workloads in your AWS environment. It supports both single-account and multi-account deployments. The framework uses AWS serverless services to gather data from the control plane and generate reports containing the status of various security checks, severity levels, and recommended actions. All assessment data remains in your own AWS account.

This assessment framework is designed for workloads using [Amazon Bedrock](https://aws.amazon.com/bedrock/), [Amazon Bedrock AgentCore](https://aws.github.io/bedrock-agentcore-starter-toolkit/), or [Amazon SageMaker AI](https://aws.amazon.com/sagemaker/ai/).

The framework performs **53 security checks** across these services, aligned with AWS Security Hub controls and security best practices:
- **Amazon Bedrock**: 14 checks (guardrails, encryption, VPC endpoints, IAM permissions)
- **Amazon SageMaker**: 26 checks (SageMaker.1-5 controls, encryption, network isolation, IAM, MLOps)
- **Amazon Bedrock AgentCore**: 13 checks (VPC configuration, encryption, observability, resource policies)


## Prerequisites

- Python 3.12+ - [Install Python](https://www.python.org/downloads/)
- AWS SAM CLI - [Install the AWS SAM CLI](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-sam-cli-install.html)
- Docker (optional) - [Install Docker community edition](https://hub.docker.com/search/?type=edition&offering=community) - Only required for local development and testing, not for AWS deployment

## Architecture

![Architecture](./generated-diagrams/ArchitectureDiagram.png)

## Single-Account Deployment

1. Download the [aiml-security-single-account.yaml](deployment/aiml-security-single-account.yaml) AWS CloudFormation template.
2. **[Deploy to AWS CloudFormation](https://console.aws.amazon.com/cloudformation/home#/stacks/create/template?stackName=resco-aiml-single-account)**
3. Upload the AWS CloudFormation template from step 1.
4. Provide a stack name and optionally specify your email address to receive notifications.
5. Leave all other parameters at their default values.
6. Navigate to the next page, read and acknowledge the notice, and click **Next**.
7. Review the information and click **Submit**.
8. Wait for the AWS CloudFormation stack to complete.
9. Once complete, AWS CodeBuild automatically deploys the assessment stack and runs the assessment.
10. To view results:
    - Navigate to the CloudFormation console
    - Open the stack you deployed (e.g., `resco-aiml-single-account` or your custom name)
    - Go to the **Outputs** tab
    - Copy the `AssessmentBucket` value
    - Navigate to that S3 bucket and open the `{account_id}/security_assessment_*.html` file

### Understanding Stack Names

The deployment creates **two types of CloudFormation stacks**:

| Stack Type | Name | Purpose |
|------------|------|---------|
| **Infrastructure Stack** | User-chosen (e.g., `my-resco-assessment`) | Contains CodeBuild, S3 bucket for results, IAM roles. This is the stack you deploy manually. |
| **Assessment Stack** | `aiml-sec-{account_id}` (auto-generated) | Contains Lambda functions and Step Functions for running checks. Created automatically by CodeBuild via SAM. |

When viewing results, use the **Infrastructure Stack** outputs (the stack you named). The assessment stack is for internal use.

## Multi-Account Deployment

### Prerequisites

- AWS Organizations setup with management account access or delegated administrator privileges.

The deployment follows a two-step approach:

### Step 1: Deploy Member Roles (StackSets)

Deploy [1-aiml-security-member-roles.yaml](deployment/1-aiml-security-member-roles.yaml) to all target accounts using AWS CloudFormation StackSets with service-managed permissions.

#### AWS Console Deployment

1. Navigate to **CloudFormation** > **StackSets** in the management account
2. Click **Create StackSet**
3. Select **Upload a template file** and upload [1-aiml-security-member-roles.yaml](deployment/1-aiml-security-member-roles.yaml)
4. Enter a StackSet name (e.g., `resco-aiml-member-roles`)
5. Set the `ReSCOAccountID` parameter to your management account ID
6. Under **Permissions**, select **Service-managed permissions**
7. Under **Deployment targets**, select the Organizational Units (OUs) containing your target accounts
8. Select **us-east-1** (or your target region) under **Specify regions**
9. Review and click **Submit**

This uses AWS Organizations to deploy the member role to all accounts in the selected OUs. New accounts added to those OUs will automatically receive the role.

### Step 2: Deploy Central Infrastructure

Deploy [2-aiml-security-codebuild.yaml](deployment/2-aiml-security-codebuild.yaml) in your central management account or delegated administrator member account.

#### AWS Console Deployment

1. Navigate to [AWS CloudFormation](https://console.aws.amazon.com/cloudformation/home#/stacks/create/template?stackName=resco-aiml-multi-account)
2. Select **Upload a template file** and upload the [2-aiml-security-codebuild.yaml](deployment/2-aiml-security-codebuild.yaml) file.
3. Set the `MultiAccountScan` parameter to `true`.
4. Optionally, provide your email address in the `EmailAddress` parameter for completion notifications.
5. Leave the remaining parameters at their default values.
6. Navigate to the next page, read and acknowledge the notice, and click **Next**.
7. Review the information and click **Submit**.
8. Stack creation automatically triggers AWS CodeBuild, which deploys the assessment to each account and runs it.

## How It Works

### Single-Account Mode (`MultiAccountScan=false`)

- Creates a local `ReSCOAIMLMemberRole`
- Runs the assessment in the same account
- Uses a local Amazon S3 bucket for results

### Multi-Account Mode (`MultiAccountScan=true`)

- Lists all active accounts in AWS Organizations
- Assumes the `ReSCOAIMLMemberRole` in each target account
- Deploys selected assessment modules in each account with a shared Amazon S3 bucket
- Executes AWS Step Functions for each deployed module in each account
- Consolidates results by assessment type in a central Amazon S3 bucket

### Assessment Execution Process

#### Automatic Trigger

- The AWS CodeBuild project starts automatically after central stack creation
- An AWS Lambda trigger function initiates the assessment workflow

#### Multi-Account Orchestration

1. **Account Discovery**: CodeBuild queries AWS Organizations for active accounts
2. **Role Assumption**: Assumes `ReSCOAIMLMemberRole` in each target account
3. **Module Deployment**: Deploys the AI/ML assessment module:
   - Amazon Bedrock Assessment Lambda
   - Amazon SageMaker Assessment Lambda
   - Amazon Bedrock AgentCore Assessment Lambda
   - AWS IAM Permission Caching Lambda
   - Consolidated Report Generation Lambda
4. **Assessment Execution**: AWS Step Functions orchestrate parallel Lambda execution
5. **Results Collection**: Individual Lambda functions store results in local S3 buckets
6. **Consolidation**: CodeBuild collects and consolidates results from all accounts
7. **Reporting**: Generates multi-account HTML and CSV reports
8. **Notification**: Sends completion notification via Amazon SNS (if configured)

## Permissions Required

### Central Account Role (`ReSCOMultiAccountCodeBuildRole`)

- Assumes roles in member accounts
- Lists AWS Organizations accounts
- Deploys AWS CloudFormation/AWS SAM applications
- Executes AWS Step Functions
- Writes to the Amazon S3 bucket

### Member Account Role (`ReSCOAIMLMemberRole`)

- Read-only access to AI/ML services (Amazon Bedrock, Amazon SageMaker, Amazon Bedrock AgentCore)
- AWS IAM read permissions for security assessment
- AWS CloudTrail, Amazon GuardDuty, and AWS Lambda read permissions
- Amazon VPC and Amazon EC2 read permissions
- Amazon ECR, Amazon CloudWatch Logs, and AWS X-Ray read permissions (for AgentCore)

## Monitoring and Results

- **Amazon S3 Bucket**: Central storage for all assessment results
- **Amazon CloudWatch Logs**: AWS CodeBuild execution logs
- **Amazon SNS Notifications**: Email alerts on completion/failure
- **Amazon EventBridge Rules**: Automated workflow triggers

## Viewing Assessment Results

You can check the AWS CodeBuild console to ensure that the assessment has completed successfully before accessing the results.

### Accessing Results

1. **Find the S3 Bucket Name**:
   - Navigate to **CloudFormation** > **Stacks** in the AWS Console
   - For single-account deployments using the standalone template (`aiml-security-single-account.yaml`), select the stack you deployed (e.g., `rescoaiml-standalonerole-mgmt`) and find the `AssessmentBucket` output. Results are synced to this bucket under the `{account_id}/` prefix.
   - For multi-account deployments, select the `resco-aiml-multi-account` stack created in [Step 2: Deploy Central Infrastructure](#step-2-deploy-central-infrastructure) and find the `AssessmentBucket` output
   - Go to the **Outputs** tab
   - Copy the S3 bucket name

   > **Note**: The deployment creates multiple S3 buckets. Only use the bucket from the `AssessmentBucket` output above. Other buckets (e.g., `aiml-sec-*-aimlassessmentbucket-*` from nested stacks or `aws-sam-cli-managed-*` for deployment artifacts) are for internal use and can be ignored.

2. **Navigate to the S3 Bucket**:
   - Go to **S3** in the AWS Console
   - Search for and open your assessment bucket
   - For single-account deployments, open the `security_assessment_XXXXX.html` report
   - For multi-account deployments, follow the [Report Structure](#report-structure) guidance below

### Report Structure

#### Consolidated Reports

- **Location**: `consolidated-reports/` folder in the bucket
- **Content**: Multi-account HTML report combining all account assessments
- **File Format**: `multi_account_report_YYYYMMDD_HHMMSS.html`
- **Features**:
  - Executive summary with metrics (Total, High, Medium, Low severity counts)
  - Service breakdown (Amazon Bedrock, Amazon SageMaker, Amazon Bedrock AgentCore)
  - Priority recommendations
  - Light/dark mode toggle (persists via localStorage)
  - Dropdown filters for Account ID, Severity, Status
  - Text search filter for findings
  - "View Docs" buttons for reference links

#### Individual Account Reports

- **Location**: Folders named with account IDs (e.g., `123456789012/`)
- **Content**: Account-specific CSV and HTML files for AI/ML assessments
- **Files Include**:
  - `bedrock_security_report_{execution_id}.csv` - Amazon Bedrock security assessment results
  - `sagemaker_security_report_{execution_id}.csv` - Amazon SageMaker security assessment results
  - `agentcore_security_report_{execution_id}.csv` - Amazon Bedrock AgentCore security assessment results
  - `permissions_cache_{execution_id}.json` - IAM permissions cache
  - `security_assessment_{timestamp}_{execution_id}.html` - Consolidated HTML report (same features as multi-account report)

### Sample Assessment Reports

The assessment generates professional HTML reports with interactive features including filtering, search, and dark mode support.

**Example reports are available in the [`sample-reports/`](sample-reports/) folder:**

- [Single Account Report](sample-reports/security_assessment_single_account.html) - Assessment for one AWS account
- [Multi-Account Report](sample-reports/security_assessment_multi_account.html) - Consolidated view across multiple accounts

The reports include:

- **Executive Summary** with severity counts and service breakdown
- **Priority Recommendations** highlighting critical issues
- **Detailed Findings Table** with filtering by account, severity, and status

### Understanding Results

| Severity | Description |
|----------|-------------|
| **High** | Critical security issues requiring immediate attention |
| **Medium** | Important security improvements recommended |
| **Low** | Minor optimizations suggested |
| **Informational** | Advisory information, no action required |
| **N/A** | Check not applicable (no resources to assess) |

| Status | Description |
|--------|-------------|
| **Failed** | Security issue identified that requires remediation |
| **Passed** | Resources were checked and found compliant |
| **N/A** | No resources exist to check (e.g., no notebooks, no guardrails configured) |

### Check ID Convention

Each security check has a unique identifier with a service prefix:
- **BR-XX**: Amazon Bedrock checks (e.g., BR-01, BR-14)
- **SM-XX**: Amazon SageMaker checks (e.g., SM-01, SM-16)
- **AC-XX**: Amazon Bedrock AgentCore checks (e.g., AC-01, AC-13)

## Customization

### Adding New Accounts

#### Option A: AWS Console

1. Navigate to **CloudFormation** > **StackSets**
2. Select `resco-aiml-member-roles` StackSet
3. Click **Add stacks to StackSet**
4. Choose deployment targets:
   - **Deploy to accounts**: Enter specific account IDs
   - **Regions**: Select target regions
5. Review and click **Submit**

### Modifying Assessment Scope

To add or remove service permissions, edit the member role permissions in `1-aiml-security-member-roles.yaml`.

### Concurrent Scanning

Adjust the `ConcurrentAccountScans` parameter based on your organization size and cost considerations.

## Troubleshooting

### Common Issues

1. **AWS CloudFormation StackSet Deployment Failures**: Check service-linked roles and permissions
2. **Cross-Account Role Assumption**: Verify trust relationships and account IDs
3. **AWS SAM Deployment Failures**: Check AWS CodeBuild logs for specific errors
4. **AWS Step Functions Execution**: Monitor state machine executions in each account
5. **EarlyValidation::ResourceExistenceCheck**: AWS CloudFormation blocks stack creation when a resource with the same physical name already exists outside of AWS CloudFormation management. This typically happens when a previous deployment failed and left behind an orphaned Amazon S3 bucket. To fix:
   - Find the orphaned bucket: `aws s3 ls | grep resco-aiml-security`
   - Empty it: `aws s3 rm s3://<bucket-name> --recursive`
   - Delete version markers if versioned: `aws s3api delete-objects --bucket <bucket-name> --delete "$(aws s3api list-object-versions --bucket <bucket-name> --query '{Objects: Versions[].{Key:Key,VersionId:VersionId}}')"`
   - Delete the bucket: `aws s3 rb s3://<bucket-name>`
   - Re-run the AWS CodeBuild project

### Debugging

- Check the AWS CodeBuild project logs in Amazon CloudWatch
- Verify cross-account role trust policies
- Ensure Amazon S3 bucket permissions allow cross-account writes
- Monitor AWS Step Functions executions for individual account assessments

## Cleanup

### Single-Account Cleanup

To remove all resources deployed for single-account assessment:

1. **Delete the AWS SAM-deployed assessment stack**:
   - Navigate to **CloudFormation** > **Stacks**
   - Select the `aiml-sec-{account_id}` stack (e.g., `aiml-sec-123456789012`)
   - Click **Delete**
   - Wait for stack deletion to complete

2. **Delete the AWS CodeBuild infrastructure stack**:
   - Select the `resco-aiml-single-account` stack (or your custom stack name)
   - Click **Delete**
   - Wait for stack deletion to complete

3. **Clean up Amazon S3 buckets** (if stack deletion fails due to non-empty buckets):
   ```bash
   # Empty the assessment bucket
   aws s3 rm s3://<assessment-bucket-name> --recursive

   # If versioning is enabled, delete version markers
   aws s3api delete-objects --bucket <bucket-name> --delete \
     "$(aws s3api list-object-versions --bucket <bucket-name> \
     --query '{Objects: Versions[].{Key:Key,VersionId:VersionId}}')"

   # Delete the bucket
   aws s3 rb s3://<bucket-name>
   ```

### Multi-Account Cleanup

To remove all resources deployed for multi-account assessment:

1. **Delete AWS SAM-deployed stacks in each member account**:
   - For each account that was scanned, navigate to **CloudFormation** > **Stacks**
   - Select the `resco-aiml-security-{account_id}` stack (e.g., `resco-aiml-security-123456789012`)
   - For the management account, select `resco-aiml-security-mgmt`
   - Click **Delete**
   - Alternatively, use the AWS CLI to delete across accounts:
     ```bash
     # Assume role in member account and delete stack
     aws cloudformation delete-stack --stack-name resco-aiml-security-<account_id> \
       --region <region>
     ```

2. **Delete the central AWS CodeBuild infrastructure stack**:
   - In the management account, navigate to **CloudFormation** > **Stacks**
   - Select the `resco-aiml-multi-account` stack
   - Click **Delete**
   - Wait for stack deletion to complete

3. **Delete the AWS CloudFormation StackSet member roles**:
   - Navigate to **CloudFormation** > **StackSets**
   - Select the `resco-aiml-member-roles` StackSet
   - Click **Actions** > **Delete stacks from StackSet**
   - Select all deployment targets (OUs or accounts)
   - Wait for stack instances to be deleted
   - Once all stack instances are removed, delete the StackSet itself

4. **Clean up Amazon S3 buckets** (if stack deletion fails due to non-empty buckets):
   ```bash
   # List and identify assessment buckets
   aws s3 ls | grep resco-aiml

   # Empty each bucket
   aws s3 rm s3://<bucket-name> --recursive

   # Delete version markers if versioning was enabled
   aws s3api delete-objects --bucket <bucket-name> --delete \
     "$(aws s3api list-object-versions --bucket <bucket-name> \
     --query '{Objects: Versions[].{Key:Key,VersionId:VersionId}}')"

   # Delete the bucket
   aws s3 rb s3://<bucket-name>
   ```

### Cleanup Order

For a clean removal, delete resources in this order:

1. **Assessment stacks** (auto-created by SAM):
   - Single-account: `aiml-sec-{account_id}` (e.g., `aiml-sec-123456789012`)
   - Multi-account: `resco-aiml-security-{account_id}` per member account, plus `resco-aiml-security-mgmt` for management account

2. **Infrastructure stack** (the stack you deployed manually):
   - Single-account: Your chosen stack name (e.g., `my-resco-assessment`)
   - Multi-account: `resco-aiml-multi-account` or your chosen name

3. AWS CloudFormation StackSet member roles (multi-account only)

4. Any remaining Amazon S3 buckets manually

## Contributing

We welcome community contributions! Please see [DEVELOPER_GUIDE.md](DEVELOPER_GUIDE.md) for guidelines.

## Security Checks Reference

### Amazon SageMaker Checks (26)

| Check ID | Check | Description | AWS Security Hub Control |
|----------|-------|-------------|--------------------------|
| SM-01 | Internet Access | Checks for direct internet access on notebooks and domains | SageMaker.2 |
| SM-02 | IAM Permissions | Identifies overly permissive policies, stale access, and SSO configuration | - |
| SM-03 | Data Protection | Verifies encryption at rest and in transit for notebooks and domains | SageMaker.1 |
| SM-04 | GuardDuty Integration | Verifies GuardDuty runtime threat detection is enabled | - |
| SM-05 | MLOps Features | Checks MLOps pipelines, experiment tracking, and model registry usage | - |
| SM-06 | Clarify Usage | Validates SageMaker Clarify for bias detection and explainability | - |
| SM-07 | Model Monitor | Checks Model Monitor configuration for drift detection | - |
| SM-08 | Model Registry | Validates model registry usage and permissions | - |
| SM-09 | Notebook Root Access | Validates root access is disabled on notebooks | SageMaker.3 |
| SM-10 | Notebook VPC Deployment | Ensures notebooks are deployed within a VPC | SageMaker.2 |
| SM-11 | Model Network Isolation | Checks inference containers have network isolation | SageMaker.4 |
| SM-12 | Endpoint Instance Count | Verifies endpoints have 2+ instances for HA | SageMaker.5 |
| SM-13 | Monitoring Network Isolation | Checks monitoring job network isolation | - |
| SM-14 | Model Container Repository | Validates model container repository access | - |
| SM-15 | Feature Store Encryption | Checks feature group encryption settings | - |
| SM-16 | Data Quality Encryption | Validates data quality job encryption | - |
| SM-17 | Processing Job Encryption | Verifies processing job encryption | - |
| SM-18 | Transform Job Encryption | Checks transform job volume encryption | - |
| SM-19 | Hyperparameter Tuning Encryption | Validates hyperparameter tuning job encryption | - |
| SM-20 | Compilation Job Encryption | Checks compilation job encryption | - |
| SM-21 | AutoML Network Isolation | Validates AutoML job network isolation | - |
| SM-22 | Model Approval Workflow | Checks model approval and governance workflow | - |
| SM-23 | Model Drift Detection | Validates model drift monitoring configuration | - |
| SM-24 | A/B Testing & Shadow Deployment | Checks for safe deployment patterns | - |
| SM-25 | ML Lineage Tracking | Validates experiment tracking and lineage | - |

### Amazon Bedrock Checks (14)

| Check ID | Check | Description |
|----------|-------|-------------|
| BR-01 | IAM Least Privilege | Identifies roles with AmazonBedrockFullAccess policy |
| BR-02 | VPC Endpoint Configuration | Validates Bedrock VPC endpoints exist for private connectivity |
| BR-03 | Marketplace Subscription Access | Checks for overly permissive marketplace subscription access |
| BR-04 | Model Invocation Logging | Checks invocation logging is enabled |
| BR-05 | Guardrail Configuration | Verifies guardrails are configured and enforced |
| BR-06 | CloudTrail Logging | Validates CloudTrail logging for Bedrock API calls |
| BR-07 | Prompt Management | Validates Bedrock Prompt template usage and variants |
| BR-08 | Agent IAM Configuration | Checks agent execution role permissions |
| BR-09 | Knowledge Base Encryption | Checks knowledge base encryption settings |
| BR-10 | Guardrail IAM Enforcement | Verifies guardrails are enforced via IAM conditions |
| BR-11 | Custom Model Encryption | Validates custom models use customer-managed KMS keys |
| BR-12 | Invocation Log Encryption | Verifies logs are encrypted with KMS |
| BR-13 | Flows Guardrails | Validates Bedrock Flows have guardrails attached |
| BR-14 | Stale Access | Detects unused Bedrock API permissions |

### Amazon Bedrock AgentCore Checks (13)

| Check ID | Check | Description |
|----------|-------|-------------|
| AC-01 | Runtime VPC Configuration | Validates agent runtimes have proper VPC settings |
| AC-02 | IAM Full Access | Checks for overly permissive AgentCore IAM policies |
| AC-03 | Stale Access | Detects unused AgentCore permissions |
| AC-04 | Observability | Verifies CloudWatch Logs and X-Ray tracing configuration |
| AC-05 | ECR Repository Encryption | Validates ECR repositories use encryption |
| AC-06 | Browser Tool Recording | Checks storage configuration for browser tools |
| AC-07 | Memory Encryption | Checks agent memory encryption with KMS |
| AC-08 | VPC Endpoints | Validates VPC endpoints for AgentCore services |
| AC-09 | Service-Linked Role | Verifies the AgentCore service-linked role exists |
| AC-10 | Resource-Based Policies | Checks runtime and gateway resource policies |
| AC-11 | Policy Engine Encryption | Validates policy engine encryption settings |
| AC-12 | Gateway Encryption | Verifies gateway encryption settings |
| AC-13 | Gateway Configuration | Validates gateway security configuration |

## Security

- All roles follow the principle of least privilege
- Cross-account trust is limited to the specific AWS CodeBuild role
- Amazon S3 bucket enforces SSL-only access
- Assessment data is encrypted in transit and at rest
- No persistent credentials are stored in AWS CodeBuild

See [Security issue notifications](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the [LICENSE](LICENSE) file.
