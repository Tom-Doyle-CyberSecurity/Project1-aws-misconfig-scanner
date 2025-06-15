import boto3
from aws_misconfig_scanner.utils.logger import setup_logger

"""
rds_scanner.py

AWS RDS Misconfiguration Scanner

This module scans AWS RDS (Relational Database Service) instances for security misconfigurations 
that may increase exposure or violate security best practices.

Misconfigurations Detected:
- Public accessibility (internet-exposed RDS instances)
- Lack of storage encryption at rest
- Missing automated backup retention

This scanner leverages the AWS SDK for Python (boto3) and integrates into a broader 
AWS misconfiguration scanning framework.

Author: Tom D.
"""

logger = setup_logger(__name__)

class RDSScanner:
    """
    Class: RDSScanner

    Description:
        Performs security misconfiguration scanning on AWS RDS instances to identify:
        - Public internet exposure
        - Disabled storage encryption
        - Missing backup retention policies

    Attributes:
        client (boto3.client): Boto3 RDS client used to retrieve instance configurations.
    """

    def __init__(self):
        """
        Initializes the RDSScanner instance and establishes connection to the AWS RDS service.
        """
        self.client = boto3.client('rds')

    def scan_rds_instances(self):
        """
        Scans all RDS instances in the AWS account for security misconfigurations.

        Checks performed:
        - Public accessibility (`PubliclyAccessible`)
        - Encryption at rest (`StorageEncrypted`)
        - Backup retention (`BackupRetentionPeriod`)

        Returns:
            findings (list): A list of dictionaries describing discovered misconfigurations.
        """
        findings = []

        try:
            instances = self.client.describe_db_instances()['DBInstances']
            for instance in instances:
                instance_id = instance['DBInstanceIdentifier']
                logger.info(f"Scanning RDS instance: {instance_id}")

                # Check public accessibility
                if instance.get('PubliclyAccessible'):
                    findings.append({
                        'InstanceId': instance_id,
                        'Issue': 'RDS instance is publicly accessible.'
                    })

                # Check storage encryption
                if not instance.get('StorageEncrypted'):
                    findings.append({
                        'InstanceId': instance_id,
                        'Issue': 'RDS storage encryption is not enabled.'
                    })

                # Check backup retention
                if instance.get('BackupRetentionPeriod', 0) == 0:
                    findings.append({
                        'InstanceId': instance_id,
                        'Issue': 'No backup retention configured.'
                    })

        except Exception as e:
            logger.error(f"Error scanning RDS instances: {e}")
            findings.append({'Error': str(e)})

        return findings