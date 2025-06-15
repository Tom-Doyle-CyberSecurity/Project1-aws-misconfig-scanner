import boto3
from aws_misconfig_scanner.utils.logger import setup_logger

"""
sg_scanner.py

AWS Security Group Misconfiguration Scanner

This module performs automated scanning of AWS Security Groups to identify
potential misconfigurations that could expose cloud infrastructure to external threats.

Specifically, it detects:
- Open ports exposed to the public internet (0.0.0.0/0)
- Dangerous or sensitive ports exposed to the public (e.g. SSH, RDP, MySQL, PostgreSQL, HTTP/HTTPS)

This scanner leverages the AWS SDK for Python (boto3) and is designed to integrate
into a broader AWS misconfiguration scanning framework.

Author: Tom D.

"""

logger = setup_logger(__name__)

# Define dangerous ports we want to flag (commonly targeted by attackers)
DANGEROUS_PORTS = [22, 3389, 3306, 5432, 80, 443]
class SGScanner:
    """
    Class: SGScanner

    Description:
        Performs security group analysis to identify publicly exposed ports
        and dangerous port exposures across all configured AWS Security groups.
    
    Attributes:
        client (boto3.client): Boto3 EC2 client used to retrieve security group configurations.
    """
    def __init__(self):
        """
       Initializes the SGScanner instance and establishes connection to the AWS EC2 service.
        """
        self.client = boto3.client('ec2')

    def scan_security_groups(self):
        """
         Scans all security groups in the AWS account and checks for:
        - Ports open to 0.0.0.0/0 (public internet)
        - Dangerous ports exposed to the public

        Returns:
            findings (list): A list of dictionaries describing discovered misconfigurations.
        """
        findings = []

        try:
            security_groups = self.client.describe_security_groups()['SecurityGroups']
            for sg in security_groups:
                sg_id = sg['GroupId']
                logger.info(f"Scanning Security Group: {sg_id}")

                for permission in sg.get('IpPermissions', []):
                    from_port = permission.get('FromPort')
                    to_port = permission.get('ToPort')

                    # Handle protocols without specific ports
                    if from_port is None or to_port is None:
                        from_port = to_port = 'All Ports'
                    
                    for ip_range in permission.get('IpRanges', []):
                        cidr_ip = ip_range.get('CidrIp')

                        # Check for unrestricted access to the internet
                        if cidr_ip == '0.0.0.0/0':
                            issue = f"Ports {from_port}-{to_port} open to the world (0.0.0.0/0)"
                            findings.append({'SecurityGroup': sg_id, 'Issue': issue})
                            logger.warning(issue)

                        # Flag highly sensitive ports if exposed publicly
                        if isinstance(from_port, int) and from_port in DANGEROUS_PORTS:
                            issue = f"Dangerous port {from_port} open to the world (0.0.0.0/0)"
                            findings.append({'SecurityGroup': sg_id, 'Issue': issue})
                            logger.warning(issue)
        except Exception as e:
            logger.error(f"Error scanning Security Groups: {e}")
            findings.append({'Error': str(e)})
        return findings