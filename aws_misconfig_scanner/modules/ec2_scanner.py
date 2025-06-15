import boto3
from aws_misconfig_scanner.utils.logger import setup_logger

"""
ec2_scanner.py

AWS EC2 Misconfiguration Scanner

This module scans AWS EC2 instances for public IP misconfigurations that may expose
virtual machines directly to the internet. EC2 instances with public IP addresses increase
attack surface and may lead to compromise if not properly secured.

Misconfiguration Detected:
- EC2 instances assigned public IP addresses.
- Public accessibility may expose services to external threats.

This scanner leverages the AWS SDK for Python (boto3) and is designed to integrate
into a broader AWS misconfiguration scanning framework.

Author: Tom D.

"""

# Configure logger for this module
logger = setup_logger(__name__)

class EC2Scanner:
    """
    Class: EC2Scanner

    Description:
        Performs EC2 instance analysis to detect public IP address assignments
        across all running instances in the AWS account
    
    Attributes:
        client (boto3.client): Boto3 EC2 client used to retrieve instance information.
    """

    def __init__(self):
        """
        Initializes the EC2Scanner instance and establishes connection to the AWS EC2 service.
        """
        self.client = boto3.client('ec2')

    def scan_ec2_instances(self):
        """
        Scans all EC2 instances across all reservations and identifies instances
        that have public IP addresses assigned.

        Public IP assignment is flagged as a potential misconfiguration, as it may expose workloads directly to the internet, increasing the attack surface.

        Returns:
            findings (list): A list of dictionaries describing discovered misconfigurations.
        """
        findings = []

        try:
            reservations = self.client.describe_instances()['Reservations']

            for reservation in reservations:
                for instance in reservation['Instances']:
                    instance_id = instance['InstanceId']
                    logger.info(f"Scanning EC2 instance: {instance_id}")

                    public_ip = instance.get('PublicIpAddress')

                    if public_ip:
                        issue = f"EC2 instance {instance_id} has a public IP address assigned: {public_ip}"
                        findings.append({'InstanceId': instance_id, 'Issue': issue})
                        logger.warning(issue)
                    else:
                        logger.info(f"EC2 instance {instance_id} has no public IP address assigned")
        except Exception as e:
            logger.error(f"Error scanning EC2 instances: {e}")
            findings.append({'Error': str(e)})

        return findings