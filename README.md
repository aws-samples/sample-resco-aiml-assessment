# AI/ML Security Assessments

## Overview

This project provides a framework for performing security assessments of AI/ML workloads in your AWS environment. It supports both single-account and multi-account deployments. The framework uses AWS serverless services to gather data from the control plane and generate reports containing the status of various security checks, severity levels, and recommended actions. All assessment data remains in your own AWS account.

This assessment framework is designed for workloads using [Amazon Bedrock](https://aws.amazon.com/bedrock/), [Amazon Bedrock AgentCore](https://aws.github.io/bedrock-agentcore-starter-toolkit/), or [Amazon SageMaker AI](https://aws.amazon.com/sagemaker/ai/).


## Prerequisites

- Python 3.12+ - [Install Python](https://www.python.org/downloads/)
- AWS SAM CLI - [Install the AWS SAM CLI](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-sam-cli-install.html)
- Docker - [Install Docker community edition](https://hub.docker.com/search/?type=edition&offering=community) [Only for local development and testing]

## Architecture

![Architecture](./generated-diagrams/ArchitectureDiagram.png)

## Single-Account Deployment

1. Download the [aiml-security-assessment-single-account.yaml](deployment/aiml-security-assessment-single-account.yaml) AWS CloudFormation template.
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
    - Open the `aiml-sec-{account_id}` stack (created by SAM, e.g., `aiml-sec-123456789012`)
    - Go to the **Outputs** tab
    - Copy the `AssessmentBucketName` value
    - Navigate to that S3 bucket and open the `security_assessment_*.html` file

## Multi-Account Deployment

### Prerequisites

- AWS Organizations setup with management account access or delegated administrator privileges.

The deployment follows a two-step approach:

### Step 1: Deploy Member Roles (StackSets)

Deploy [1-resco-member-roles.yaml](deployment/1-resco-member-roles.yaml) to all target accounts using AWS CloudFormation StackSets with service-managed permissions.

#### AWS Console Deployment

1. Navigate to **CloudFormation** > **StackSets** in the management account
2. Click **Create StackSet**
3. Select **Upload a template file** and upload [1-resco-member-roles.yaml](deployment/1-resco-member-roles.yaml)
4. Enter a StackSet name (e.g., `resco-aiml-member-roles`)
5. Set the `ReSCOAccountID` parameter to your management account ID
6. Under **Permissions**, select **Service-managed permissions**
7. Under **Deployment targets**, select the Organizational Units (OUs) containing your target accounts
8. Select **us-east-1** (or your target region) under **Specify regions**
9. Review and click **Submit**

This uses AWS Organizations to deploy the member role to all accounts in the selected OUs. New accounts added to those OUs will automatically receive the role.

### Step 2: Deploy Central Infrastructure

Deploy [2-resco-assessment-codebuild.yaml](deployment/2-resco-assessment-codebuild.yaml) in your central management account or delegated administrator member account.

#### AWS Console Deployment

1. Navigate to [AWS CloudFormation](https://console.aws.amazon.com/cloudformation/home#/stacks/create/template?stackName=resco-aiml-multi-account)
2. Select **Upload a template file** and upload the [2-resco-assessment-codebuild.yaml](deployment/2-resco-assessment-codebuild.yaml) file.
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
   - For single-account deployments, select the `aiml-sec-{account_id}` stack (e.g., `aiml-sec-123456789012`)
   - For multi-account deployments, select the `resco-aiml-multi-account` stack created in [Step 2: Deploy Central Infrastructure](#step-2-deploy-central-infrastructure)
   - Go to the **Outputs** tab
   - Copy the S3 bucket name from the `AssessmentBucketName` output

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
  - `security_assessment_{timestamp}_{execution_id}.html` - Consolidated HTML report (same features as multi-account report)

### Sample Assessment Report

The consolidated report provides a comprehensive view of security findings across all accounts. In the HTML report, reference links appear as "View Docs" buttons with tooltips showing the full URL:

| Account ID   | Finding                                | Finding Details                                 | Resolution                                                    | Reference                                                                                                      | Severity | Status |
| ------------ | -------------------------------------- | ----------------------------------------------- | ------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | -------- | ------ |
| 3183XXXX3611 | Bedrock Model Invocation Logging Check | Model invocation logging is not enabled         | Enable logging to S3 or CloudWatch for audit tracking         | [Model Invocation Logging](https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html) | Medium   | Failed |
| 3183XXXX3611 | Bedrock Guardrails Check               | No Guardrails configured                        | Configure content filters and safety measures                 | [Bedrock Guardrails](https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails.html)                     | Medium   | Failed |
| 3183XXXX3611 | Bedrock CloudTrail Logging Check       | CloudTrail not configured for Bedrock API calls | Enable CloudTrail logging for audit compliance                | [CloudTrail Logging](https://docs.aws.amazon.com/bedrock/latest/userguide/logging-using-cloudtrail.html)       | High     | Failed |
| 3183XXXX3611 | AgentCore Runtime VPC Configuration    | Runtime not configured with VPC                 | Configure VPC with private subnets and required VPC endpoints | [AgentCore VPC](https://aws.github.io/bedrock-agentcore-starter-toolkit/user-guide/security/agentcore-vpc.md)  | High     | Failed |
| 3183XXXX3611 | AgentCore Memory Encryption            | Memory without customer-managed encryption      | Enable encryption with customer-managed KMS keys              | [AgentCore Memory](https://aws.github.io/bedrock-agentcore-starter-toolkit/user-guide/memory/)                 | Medium   | Failed |
| 3183XXXX3611 | SageMaker Model Registry Issue         | No model package groups found                   | Implement model versioning and lifecycle management           | [MLOps Guide](https://docs.aws.amazon.com/sagemaker/latest/dg/mlops.html)                                      | Medium   | Failed |

### Understanding Results

- **Severity Levels**:
  - **High**: Critical security issues requiring immediate attention
  - **Medium**: Important security improvements recommended
  - **Low**: Minor optimizations suggested
  - **N/A**: No issues found, or check is not applicable

- **Status**:
  - **Failed**: Security issue identified
  - **Passed**: No issues found
  - **N/A**: Check is not applicable to the current configuration

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

To add or remove service permissions, edit the member role permissions in `1-resco-member-roles.yaml`.

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
   - Select the `aiml-sec-{account_id}` stack
   - Click **Delete**
   - Alternatively, use the AWS CLI to delete across accounts:
     ```bash
     # Assume role in member account and delete stack
     aws cloudformation delete-stack --stack-name aiml-sec-<account_id> \
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
1. AWS SAM-deployed assessment stacks (`aiml-sec-*`) in all accounts
2. Central infrastructure stack (`resco-aiml-single-account` or `resco-aiml-multi-account`)
3. AWS CloudFormation StackSet member roles (multi-account only)
4. Any remaining Amazon S3 buckets manually

## Contributing

We welcome community contributions! Please see [DEVELOPER_GUIDE.md](DEVELOPER_GUIDE.md) for guidelines.

## Security

- All roles follow the principle of least privilege
- Cross-account trust is limited to the specific AWS CodeBuild role
- Amazon S3 bucket enforces SSL-only access
- Assessment data is encrypted in transit and at rest
- No persistent credentials are stored in AWS CodeBuild

See [Security issue notifications](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the [LICENSE](LICENSE) file.
