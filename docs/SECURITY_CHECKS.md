# Security Checks Reference

This document provides a comprehensive reference for all 52 security checks performed by the AI/ML Security Assessment framework.

## Table of Contents

- [Overview](#overview)
- [Check ID Convention](#check-id-convention)
- [Severity Levels](#severity-levels)
- [Status Values](#status-values)
- [Amazon SageMaker Checks (25)](#amazon-sagemaker-checks-25)
- [Amazon Bedrock Checks (14)](#amazon-bedrock-checks-14)
- [Amazon Bedrock AgentCore Checks (13)](#amazon-bedrock-agentcore-checks-13)

---

## Overview

The framework evaluates your AI/ML workloads against AWS security best practices across three services:

| Service | Number of Checks | Focus Areas |
|---------|------------------|-------------|
| Amazon SageMaker AI | 25 | Security Hub controls, encryption, network isolation, IAM, MLOps |
| Amazon Bedrock | 14 | Guardrails, encryption, VPC endpoints, IAM permissions, logging |
| Amazon Bedrock AgentCore | 13 | VPC configuration, encryption, observability, resource policies |

---

## Check ID Convention

Each security check has a unique identifier with a service prefix:

| Prefix | Service | Example |
|--------|---------|---------|
| **SM-XX** | Amazon SageMaker | SM-01, SM-25 |
| **BR-XX** | Amazon Bedrock | BR-01, BR-14 |
| **AC-XX** | Amazon Bedrock AgentCore | AC-01, AC-13 |

---

## Severity Levels

| Severity | Description | Action Required |
|----------|-------------|-----------------|
| **High** | Critical security issues that could lead to data exposure, unauthorized access, or compliance violations | Immediate remediation recommended |
| **Medium** | Important security improvements that strengthen your security posture | Address in next maintenance window |
| **Low** | Minor optimizations and best practice recommendations | Address when convenient |
| **Informational** | Advisory information about your configuration | No action required |
| **N/A** | Check not applicable (no resources to assess) | No action required |

---

## Status Values

| Status | Description |
|--------|-------------|
| **Failed** | Security issue identified that requires remediation |
| **Passed** | Resources were checked and found compliant |
| **N/A** | No resources exist to check (e.g., no notebooks, no guardrails configured) |

---

## Amazon SageMaker Checks (25)

### Core Security Controls

| Check ID | Check Name | Description | Severity | AWS Security Hub Control |
|----------|------------|-------------|----------|--------------------------|
| SM-01 | Internet Access | Checks for direct internet access on notebooks and domains | High | SageMaker.2 |
| SM-02 | AWS IAM Permissions | Identifies overly permissive policies, stale access, and SSO configuration | High | - |
| SM-03 | Data Protection | Verifies encryption at rest and in transit for notebooks and domains | High | SageMaker.1 |
| SM-04 | Amazon GuardDuty Integration | Verifies Amazon GuardDuty runtime threat detection is enabled | Medium | - |
| SM-09 | Notebook Root Access | Validates root access is disabled on notebooks | High | SageMaker.3 |
| SM-10 | Notebook Amazon VPC Deployment | Ensures notebooks are deployed within an Amazon VPC | High | SageMaker.2 |
| SM-11 | Model Network Isolation | Checks inference containers have network isolation | Medium | SageMaker.4 |
| SM-12 | Endpoint Instance Count | Verifies endpoints have 2+ instances for high availability | Medium | SageMaker.5 |

### MLOps and Governance

| Check ID | Check Name | Description | Severity | AWS Security Hub Control |
|----------|------------|-------------|----------|--------------------------|
| SM-05 | MLOps Features | Checks MLOps pipelines, experiment tracking, and model registry usage | Low | - |
| SM-06 | Clarify Usage | Validates SageMaker Clarify for bias detection and explainability | Low | - |
| SM-07 | Model Monitor | Checks Model Monitor configuration for drift detection | Medium | - |
| SM-08 | Model Registry | Validates model registry usage and permissions | Medium | - |
| SM-22 | Model Approval Workflow | Checks model approval and governance workflow | Medium | - |
| SM-23 | Model Drift Detection | Validates model drift monitoring configuration | Medium | - |
| SM-24 | A/B Testing & Shadow Deployment | Checks for safe deployment patterns | Low | - |
| SM-25 | ML Lineage Tracking | Validates experiment tracking and lineage | Low | - |

### Encryption Checks

| Check ID | Check Name | Description | Severity | AWS Security Hub Control |
|----------|------------|-------------|----------|--------------------------|
| SM-13 | Monitoring Network Isolation | Checks monitoring job network isolation | Medium | - |
| SM-14 | Model Container Repository | Validates model container repository access | Medium | - |
| SM-15 | Feature Store Encryption | Checks feature group encryption settings | High | - |
| SM-16 | Data Quality Encryption | Validates data quality job encryption | Medium | - |
| SM-17 | Processing Job Encryption | Verifies processing job encryption | Medium | - |
| SM-18 | Transform Job Encryption | Checks transform job volume encryption | Medium | - |
| SM-19 | Hyperparameter Tuning Encryption | Validates hyperparameter tuning job encryption | Medium | - |
| SM-20 | Compilation Job Encryption | Checks compilation job encryption | Medium | - |
| SM-21 | AutoML Network Isolation | Validates AutoML job network isolation | Medium | - |

---

## Amazon Bedrock Checks (14)

### Access Control

| Check ID | Check Name | Description | Severity |
|----------|------------|-------------|----------|
| BR-01 | AWS IAM Least Privilege | Identifies roles with AmazonBedrockFullAccess policy | High |
| BR-03 | Marketplace Subscription Access | Checks for overly permissive marketplace subscription access | Medium |
| BR-08 | Agent AWS IAM Configuration | Checks agent execution role permissions | Medium |
| BR-10 | Guardrail AWS IAM Enforcement | Verifies guardrails are enforced via AWS IAM conditions | Medium |
| BR-14 | Stale Access | Detects unused Bedrock API permissions | Low |

### Network Security

| Check ID | Check Name | Description | Severity |
|----------|------------|-------------|----------|
| BR-02 | Amazon VPC Endpoint Configuration | Validates Bedrock Amazon VPC endpoints exist for private connectivity | High |

### Data Protection

| Check ID | Check Name | Description | Severity |
|----------|------------|-------------|----------|
| BR-09 | Knowledge Base Encryption | Checks knowledge base encryption settings | High |
| BR-11 | Custom Model Encryption | Validates custom models use customer-managed AWS KMS keys | High |
| BR-12 | Invocation Log Encryption | Verifies logs are encrypted with AWS KMS | Medium |

### Guardrails and Safety

| Check ID | Check Name | Description | Severity |
|----------|------------|-------------|----------|
| BR-05 | Guardrail Configuration | Verifies guardrails are configured and enforced | High |
| BR-07 | Prompt Management | Validates Bedrock Prompt template usage and variants | Low |
| BR-13 | Flows Guardrails | Validates Bedrock Flows have guardrails attached | Medium |

### Logging and Monitoring

| Check ID | Check Name | Description | Severity |
|----------|------------|-------------|----------|
| BR-04 | Model Invocation Logging | Checks invocation logging is enabled | Medium |
| BR-06 | AWS CloudTrail Logging | Validates AWS CloudTrail logging for Bedrock API calls | Medium |

---

## Amazon Bedrock AgentCore Checks (13)

### Network Configuration

| Check ID | Check Name | Description | Severity |
|----------|------------|-------------|----------|
| AC-01 | Runtime Amazon VPC Configuration | Validates agent runtimes have proper Amazon VPC settings | High |
| AC-08 | Amazon VPC Endpoints | Validates Amazon VPC endpoints for AgentCore services | High |

### Access Control

| Check ID | Check Name | Description | Severity |
|----------|------------|-------------|----------|
| AC-02 | AWS IAM Full Access | Checks for overly permissive AgentCore AWS IAM policies | High |
| AC-03 | Stale Access | Detects unused AgentCore permissions | Low |
| AC-09 | Service-Linked Role | Verifies the AgentCore service-linked role exists | Medium |
| AC-10 | Resource-Based Policies | Checks runtime and gateway resource policies | Medium |

### Data Protection

| Check ID | Check Name | Description | Severity |
|----------|------------|-------------|----------|
| AC-05 | Amazon ECR Repository Encryption | Validates Amazon ECR repositories use encryption | High |
| AC-06 | Browser Tool Recording | Checks storage configuration for browser tools | Medium |
| AC-07 | Memory Encryption | Checks agent memory encryption with AWS KMS | High |
| AC-11 | Policy Engine Encryption | Validates policy engine encryption settings | Medium |
| AC-12 | Gateway Encryption | Verifies gateway encryption settings | Medium |
| AC-13 | Gateway Configuration | Validates gateway security configuration | Medium |

### Observability

| Check ID | Check Name | Description | Severity |
|----------|------------|-------------|----------|
| AC-04 | Observability | Verifies Amazon CloudWatch Logs and AWS X-Ray tracing configuration | Medium |

---

## Additional Resources

- [Amazon SageMaker Security Best Practices](https://docs.aws.amazon.com/sagemaker/latest/dg/security.html)
- [Amazon Bedrock Security](https://docs.aws.amazon.com/bedrock/latest/userguide/security.html)
- [AWS Security Hub SageMaker Controls](https://docs.aws.amazon.com/securityhub/latest/userguide/sagemaker-controls.html)
- [AWS Well-Architected Framework - Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html)
