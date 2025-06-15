from aws_misconfig_scanner.modules.ec2_scanner import EC2Scanner
from aws_misconfig_scanner.modules.iam_scanner import IAMScanner
from aws_misconfig_scanner.modules.lambda_scanner import LambdaScanner
from aws_misconfig_scanner.modules.rds_scanner import RDSScanner
from aws_misconfig_scanner.modules.s3_scanner import S3Scanner
from aws_misconfig_scanner.modules.sg_scanner import SGScanner
from aws_misconfig_scanner.utils.logger import setup_logger



"""
main.py

AWS Misconfiguration Scanner Orchestrator

This file orchestrates the execution of multiple AWS misconfiguration scanners across core AWS services, including:
- EC2 (Elastic Compute Cloud)
- IAM (Identity and Access Management)
- Lambda (Serverless Functions)
- RDS (Relational Database Service)
- S3 (Simple Storage Service)
- Security Groups (VPC firewall rules)

Each scanner analyzes a specific AWS service for potential misconfigurations and collects security findings.

Author: Tom D.
"""

logger = setup_logger(__name__)

class AWSMisconfigurationScanner:
    """
    Class: AWSMisconfigurationScanner

    Description:
        Master orchestrator that sequentially executes all AWS service-specific misconfiguration scanners
        and consolidates security findings across the cloud environment.
    
    Attributes:
        ec2_scanner (EC2Scanner): EC2 instance scanner.
        iam_scanner (IAMScanner): IAM configuration scanner.
        lambda_scanner (LambdaScanner): Lambda function scanner.
        rds_scanner (RDSScanner): RDS database scanner.
        sg_scanner (SGScanner): Security Group misconfiguration scanner.
        s3_scanner (S3Scanner): S3 bucket scanner.
    """

    def __init__(self):
        """
        Initializes the orchestrator and all individual scanner modules.
        """
        self.ec2_scanner = EC2Scanner()
        self.iam_scanner = IAMScanner()
        self.lambda_scanner = LambdaScanner()
        self.rds_scanner = RDSScanner()
        self.sg_scanner = SGScanner()
        self.s3_scanner = S3Scanner()
    
    def run_all_scans(self):
        """
        Executes all scanners sequentially and collects their findings.

        Returns:
            findings (dict): A dictionary containing security findings categorized by AWS service.
        """
        logger.info("===== Starting AWS Misconfiguration Scan =====")
        findings = {}
        
        # EC2 Scan
        logger.info("Running EC2 Scanner...")
        findings['EC2'] = self.ec2_scanner.scan_ec2_instances()
        
        # IAM Scan
        logger.info("Running IAM Scanner...")
        findings['IAM'] = self.iam_scanner.run_all_checks()  # IAM scanner handles logging itself

        # Lambda Scan
        logger.info("Running Lambda Scanner...")
        findings['Lambda'] = self.lambda_scanner.scan_lambda_functions()

        # RDS Scan
        logger.info("Running RDS Scanner...")
        findings['RDS'] = self.rds_scanner.scan_rds_instances()

        # Security Group Scan
        logger.info("Running Security Group Scanner...")
        findings['SecurityGroups'] = self.sg_scanner.scan_security_groups()

        # S3 Scan
        logger.info("Running S3 Scanner...")
        findings['S3'] = self.s3_scanner.scan_s3_buckets()

        logger.info("===== AWS Misconfiguration Scan Completed =====")
        return findings

if __name__ == "__main__":
    scanner = AWSMisconfigurationScanner()
    results = scanner.run_all_scans()

    # Print consolidated findings
    print("\n=== Misconfiguration Findings Summary ===\n")
    for service, service_findings in results.items():
        print(f"\nService: {service}")
        if not service_findings:
            print("  No misconfigurations found.")
        else:
            for finding in service_findings:
                print(f"  - {finding}")