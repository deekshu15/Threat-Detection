# AI-Assisted Threat Detection Dashboard

## Overview

This directory contains the complete CloudFormation Infrastructure-as-Code
(IaC) templates required to deploy the AI-Assisted Threat Detection Dashboard
on AWS.

The infrastructure provisions networking, IAM, storage, databases,
serverless compute, API Gateway, authentication, streaming, analytics,
monitoring, and reporting resources.

---

# Directory Structure

```
cloudformation/

├── README.md
├── master.yaml
├── parameters.json
├── networking.yaml
├── iam.yaml
├── s3.yaml
├── dynamodb.yaml
├── lambda.yaml
├── api-gateway.yaml
├── sns.yaml
├── kinesis.yaml
├── quicksight.yaml
├── cognito-user-pool.yaml
├── monitoring.yaml
└── outputs.yaml
```

---

# Infrastructure Components

## Networking

- VPC
- Public Subnet
- Private Subnet
- Internet Gateway
- Route Tables
- Security Groups

---

## IAM

Creates

- Lambda Execution Role
- API Gateway Role
- CloudWatch Role
- IAM Policies

---

## Amazon S3

Creates

- Raw Logs Bucket
- Processed Logs Bucket
- ML Models Bucket
- Reports Bucket

Features

- Versioning
- Encryption
- Lifecycle Rules
- Public Access Blocking

---

## DynamoDB

Creates

- Threat Table
- IOC Table
- Asset Table
- Incident Table
- User Table

Features

- Point-in-Time Recovery
- Global Secondary Indexes
- Server-side Encryption
- TTL

---

## AWS Lambda

Deploys

- Threat Enrichment
- Feature Engineering
- ML Engine
- Risk Engine
- Recommendation Engine
- Incident Correlation

---

## API Gateway

Creates

- REST API
- Resources
- Methods
- Lambda Integrations
- Production Stage

---

## Amazon SNS

Creates

- Critical Alerts
- High Alerts
- Medium Alerts

Supports

- Email Notifications
- SMS Notifications

---

## Amazon Kinesis

Creates

- Data Stream
- Firehose
- Analytics Application

---

## Amazon QuickSight

Creates

- Athena Data Source
- Dataset
- Analysis
- Dashboard

---

## Amazon Cognito

Creates

- User Pool
- App Client

---

## Monitoring

Creates

- CloudWatch Dashboard
- Alarms
- EventBridge Rules
- Log Groups

---

# Deployment Order

Deploy stacks in the following order.

1. networking.yaml

2. iam.yaml

3. s3.yaml

4. dynamodb.yaml

5. lambda.yaml

6. api-gateway.yaml

7. sns.yaml

8. kinesis.yaml

9. quicksight.yaml

10. cognito-user-pool.yaml

11. monitoring.yaml

12. outputs.yaml

Or deploy everything using

master.yaml

---

# Deployment

Deploy the master stack.

```bash
aws cloudformation deploy \
    --stack-name ThreatDetection \
    --template-file master.yaml \
    --parameter-overrides file://parameters.json \
    --capabilities CAPABILITY_NAMED_IAM
```

---

# Updating Infrastructure

```bash
aws cloudformation deploy \
    --stack-name ThreatDetection \
    --template-file master.yaml \
    --parameter-overrides file://parameters.json \
    --capabilities CAPABILITY_NAMED_IAM
```

CloudFormation will update only the resources that changed.

---

# Deleting Infrastructure

```bash
aws cloudformation delete-stack \
    --stack-name ThreatDetection
```

---

# Requirements

- AWS CLI v2
- CloudFormation
- Python 3.12
- IAM permissions
- AWS Account
- S3 deployment bucket
- Lambda deployment packages

---

# Deployment Packages

Upload Lambda ZIP packages before deployment.

Example

```
threat_enrichment.zip
feature_engineering.zip
ml_engine.zip
risk_engine.zip
recommendation_engine.zip
incident_correlation.zip
```

These packages should exist in the Lambda deployment bucket.

---

# Stack Dependencies

```
Networking
      │
      ▼
IAM
      │
      ▼
S3 ───── DynamoDB
      │
      ▼
Lambda
      │
      ▼
API Gateway
      │
      ▼
SNS
      │
      ▼
Monitoring

Kinesis

QuickSight

Cognito
```

---

# Outputs

CloudFormation exports

- VPC ID
- Security Group
- S3 Buckets
- DynamoDB Tables
- Lambda ARNs
- API Endpoint
- SNS Topics
- Kinesis Stream
- QuickSight Dashboard

---

# Troubleshooting

## Stack Failed

View events

```bash
aws cloudformation describe-stack-events \
    --stack-name ThreatDetection
```

---

## Validate Template

```bash
aws cloudformation validate-template \
    --template-body file://master.yaml
```

---

## List Stacks

```bash
aws cloudformation list-stacks
```

---

## View Outputs

```bash
aws cloudformation describe-stacks \
    --stack-name ThreatDetection
```

---

# Security Recommendations

- Enable AWS Config
- Enable CloudTrail
- Enable GuardDuty
- Enable Security Hub
- Use KMS-managed encryption
- Rotate IAM credentials
- Enable MFA
- Follow least-privilege IAM policies

---

# License

Internal project for the AI-Assisted Threat Detection Dashboard.