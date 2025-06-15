import boto3
from aws_misconfig_scanner.utils.logger import setup_logger

"""
lambda_scanner.py

AWS Lambda Misconfiguration Scanner

This module scans AWS Lambda functions for common misconfigurations including:
- Missing environment variable encryption (no KMS key assigned)
- Unrestricted concurrency (no reserved concurrency limits)
- Attached resource policies that may introduce overly permissive access

This scanner leverages the AWS SDK for Python (boto3) and is designed to integrate into a broader AWS misconfiguration scanning framework.

Author: Tom D.
"""

logger = setup_logger(__name__)

class LambdaScanner:
    """
    Class: LambdaScanner

    Description:
        Performs AWS Lambda configuration analysis to detect misconfigurations related to:
        - Environment variable encryption (KMS key presence)
        - Reserved concurrency enforcement
        - Resource policy existence

    Attributes:
        client (boto3.client): Boto3 Lambda client used to retrieve function configurations.
    """

    def __init__(self):
        """
        Initializes the LambdaScanner instance and establishes connection to the AWS Lambda service.
        """
        self.client = boto3.client('lambda')

    def scan_lambda_functions(self):
        """
        Scans all Lambda functions in the AWS account and evaluates potential misconfigurations.

        Checks performed:
        - Absence of KMS key for environment variable encryption
        - Missing reserved concurrency settings
        - Attached resource policies (may require further analysis)

        Returns:
            findings (list): A list of dictionaries describing discovered misconfigurations.
        """
        findings = []

        try:
            paginator = self.client.get_paginator('list_functions')
            for page in paginator.paginate():
                for function in page['Functions']:
                    function_name = function['FunctionName']
                    logger.info(f"Scanning Lambda function: {function_name}")

                    # Check environment variables encryption
                    if 'KMSKeyArn' not in function:
                        findings.append({
                            'FunctionName': function_name,
                            'Issue': 'Environment variables are not encrypted with KMS.'
                        })

                    # Check reserved concurrency
                    concurrency = self.client.get_function_concurrency(FunctionName=function_name)
                    if 'ReservedConcurrentExecutions' not in concurrency:
                        findings.append({
                            'FunctionName': function_name,
                            'Issue': 'No reserved concurrency set.'
                        })

                    # Check attached resource policy (overly permissive potential)
                    policy = self.client.get_policy(FunctionName=function_name)
                    if 'Policy' in policy:
                        findings.append({
                            'FunctionName': function_name,
                            'Issue': 'Function has resource policy attached; review for overly permissive access.'
                        })

        except Exception as e:
            logger.error(f"Error scanning Lambda functions: {e}")
            findings.append({'Error': str(e)})

        return findings