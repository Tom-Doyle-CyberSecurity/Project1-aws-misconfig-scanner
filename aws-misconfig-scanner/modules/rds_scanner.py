import boto3
from utils.logger import setup_logger

"""
rds_scanner.py

AWS RDS Misconfiguration Scanner

This module scans AWS RDS instances for common security misconfigurations such as:
- Public accessibility
- Encryption at rest not enabled
- No backup retention

Author: Tom D.
"""

logger = setup_logger(__name__)

class RDSScanner:
    def __init__(self):
        self.client = boto3.client('rds')

    def scan_rds_instances(self):
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