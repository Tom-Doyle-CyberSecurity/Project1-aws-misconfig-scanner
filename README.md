# AWS Misconfiguration Scanner

**Assessment Report**

  Prepared by: Tom Doyle
  
  Date: 16/06/2025
  
  Version: 1.0

**Automated AWS Cloud Security Scanner**  
This tool performs automated scanning across AWS services to detect common cloud misconfigurations that may lead to security exposure or violate AWS best practices.

## Acronyms

|  Acronym  |            Definition         |
|-----------|-------------------------------|
|    AWS    | Amazon Web Services           |
|    IAM    | Identity and Access Management|
|    MFA    | Multi-Factor Authentication   |
|    RDA    | Relational Database Service   |
|    S3     | Simple Storage Service        |
|    EC2    | Elastic Compute               |
|    SDK    | Software Development Kit      |

## 1. Executive Summary
- This report presents the outcomes of an automated AWS Misconfiguration Scanner designed to identify and validate security misconfigurations across critical AWS services. The assessment focuses on detecting weaknesses that could lead to data breaches, unauthorized access, or compliance violations. The evaluation identified multiple critical and high-risk misconfigurations across core AWS services, exposing the environment to potential data compromise, privilege escalation, and compliance violations. Findings include IAM privilege escalation, publicly accessible resources, and insecure storage configurations, posing significant security, compliance, and business risks.

## 2. Introduction
- The AWS Misconfiguration Scanner automatically evaluates configurations across key AWS services, including EC2, IAM, Lambda, S3, RDS, and Security Groups. The scanner is designed to detect misconfigurations such as:
    - Publicly exposed compute, storage, and database resources
    - Excessive IAM privileges and administrative role assignments
    - Public S3 bucket access and missing versioning/encryption
    - Unused or stale IAM access keys
    - Unrestricted network security group ingress rules
 
  The results enable proactive remediation to strengthen security posture and reduce the opportunities to exploit poor configuration or weaknesses

## 3. Limitations and Scope
- The assessment was performed in a controlled AWS environment designed to simulate common misconfiguration scenarios. The scanner was tested against intentionally vulnerable AWS resources to validate detection capabilities. This report does not represent a full enterprise security audit or penetration test. All findings are limited to configurations actively deployed at the time of assessment

## 4. Methodology - Scanning Approach
- The scanner was built using the AWS SDK for Python (boto3)
- Each AWS service is queried via its respective API client
- Misconfigurations are detected through rule-based checks comparing resource configurations to AWS

## 4.1 Tech Stack

- Python 3.11
- Primary library: boto3 (AWS SDK for Python)
- Execution environment: Local Python scripts, GitHub Codespace, Docker
- Modules: Each AWS service scanner (e.g., ec2_scanner.py, s3_scanner.py) is modularized for maintainability
- Reporting: Terminal output listing scanner misconfiguration findings, transfered technical findings into structured report
- CI/CD integration: Scanners can be integrated into GitHub Actions for automated scanning (optional/future scope)
- Logging: Standard logging module used to track scanner activity and errors

## 4.2 Services Scanned

- **EC2** -> Detects public IP exposure on EC2 instances
- **IAM** -> Checks for root account usage, overly permissive wildcard policies, inactive access keys
- **Lambda** -> Verifies environment encryption, concurrency limits, resource policies
- **RDS** -> Detects public accessibility, disabled encryption, missing backup retention
- **S3** -> Identifies public buckets, missing encryption, missing versioning
- **Security Groups** -> Finds open ports and dangerous service exposures (e.g., SSH, RDP, databases)

## Figure 1: AWS Misconfiguration Scanner Architecture and Coverage

## 5. Technical Findings

|  Service  |             Finding          |  Risk    |                                 Description                                              |
|-----------|------------------------------|----------|------------------------------------------------------------------------------------------|
|    EC2    |  Public IP exposure          |  High    | Instance **i-0e9dffb42da5db6ee** is publicly accessible via assigned IP <IP Address>     |
|IAM (Users)|  AdministratorAccess attached|  Critical| User **misconfig-scanner-user** has **AdministratorAccess** permissions directly assigned|



---

## ⬇ Installation

1️⃣ Clone the repository:

```bash
git clone https://github.com/<Tom-Doyle-CyberSecurity>/aws-misconfig-scanner.git
cd aws-misconfig-scanner
