import botocore
import boto3
from aws_misconfig_scanner.utils.logger import setup_logger

"""
s3_scanner.py

AWS S3 Misconfiguration Scanner

This module scans AWS S3 (Simple Storage Service) buckets for security misconfigurations 
that may expose sensitive data or violate AWS security best practices.

Misconfigurations Detected:
- Public bucket accessibility (ACL or policy)
- Disabled encryption at rest
- Absence of versioning configuration

This scanner leverages the AWS SDK for Python (boto3) and integrates into a broader 
AWS misconfiguration scanning framework.

Author: Tom D.
"""

logger = setup_logger(__name__)

class S3Scanner:
    """
    Class: S3Scanner

    Description:
        Performs security misconfiguration scanning on AWS S3 buckets to identify:
        - Public accessibility
        - Lack of encryption
        - Missing versioning

    Attributes:
        client (boto3.client): Boto3 S3 client used to retrieve bucket configurations.
    """

    def __init__(self):
        """
        Initializes the S3Scanner instance and establishes connection to the AWS S3 service.
        """
        self.client = boto3.client('s3')

    def scan_s3_buckets(self):
        """
        Scans all S3 buckets in the AWS account for security misconfigurations.

        Checks performed:
        - Public accessibility (ACL and bucket policy)
        - Encryption at rest (SSE configuration)
        - Versioning configuration

        Returns:
            findings (list): A list of dictionaries describing discovered misconfigurations.
        """
        findings = []

        try:
            response = self.client.list_buckets()
            buckets = response.get('Buckets', [])

            for bucket in buckets:
                bucket_name = bucket['Name']
                logger.info(f"Scanning S3 bucket: {bucket_name}")

                # Check public ACL access
                acl = self.client.get_bucket_acl(Bucket=bucket_name)
                for grant in acl.get('Grants', []):
                    grantee = grant.get('Grantee', {})
                    permission = grant.get('Permission')
                    if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                        findings.append({
                            'Bucket': bucket_name,
                            'Issue': f'Bucket ACL allows public access ({permission}).'
                        })

                # Check public bucket policy
                try:
                    policy_status = self.client.get_bucket_policy_status(Bucket=bucket_name)
                    if policy_status['PolicyStatus'].get('IsPublic'):
                        findings.append({
                            'Bucket': bucket_name,
                            'Issue': 'Bucket policy allows public access.'
                        })
                except botocore.exceptions.ClientError as e:
                    error_code = e.response['Error']['Code']
                    if error_code == 'NoSuchBucketPolicy':
                        logger.info(f"No bucket policy found for {bucket_name}.")
                    else:
                        logger.error(f"Error checking bucket policy for {bucket_name}: {e}")
                except Exception as e:
                    logger.error(f"Unhandled error checking bucket policy for {bucket_name}: {e}")

                # Check encryption at rest
                try:
                    encryption = self.client.get_bucket_encryption(Bucket=bucket_name)
                    rules = encryption['ServerSideEncryptionConfiguration']['Rules']
                    if not rules:
                        findings.append({
                            'Bucket': bucket_name,
                            'Issue': 'No server-side encryption configured.'
                        })
                except botocore.exceptions.ClientError as e:
                    if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                        findings.append({
                            'Bucket': bucket_name,
                            'Issue': 'No server-side encryption configured.'
                        })
                    else:
                        logger.error(f"Error checking encryption for {bucket_name}: {e}")

                # Check versioning configuration
                versioning = self.client.get_bucket_versioning(Bucket=bucket_name)
                if versioning.get('Status') != 'Enabled':
                    findings.append({
                        'Bucket': bucket_name,
                        'Issue': 'Bucket versioning is not enabled.'
                    })

        except Exception as e:
            logger.error(f"Error scanning S3 buckets: {e}")
            findings.append({'Error': str(e)})

        return findings