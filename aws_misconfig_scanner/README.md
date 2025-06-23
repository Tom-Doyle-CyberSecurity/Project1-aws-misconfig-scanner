# AWS Misconfiguration Scanner

**Automated AWS Cloud Security Scanner**  
This tool performs automated scanning across AWS services to detect common cloud misconfigurations that may lead to security exposure or violate AWS best practices.

---

## Services Scanned

- **EC2**: Detects public IP exposure on EC2 instances
- **IAM**: Checks for root account usage, overly permissive wildcard policies, inactive access keys
- **Lambda**: Verifies environment encryption, concurrency limits, resource policies
- **RDS**: Detects public accessibility, disabled encryption, missing backup retention
- **S3**: Identifies public buckets, missing encryption, missing versioning
- **Security Groups**: Finds open ports and dangerous service exposures (e.g., SSH, RDP, databases)

---

## Tech Stack

- Python 3.x
- AWS SDK for Python (`boto3`)
- Modular architecture (service-specific scanners)
- Logging and error handling framework

---

## ⬇ Installation

1️⃣ Clone the repository:

```bash
git clone https://github.com/<Tom-Doyle-CyberSecurity>/aws-misconfig-scanner.git
cd aws-misconfig-scanner
