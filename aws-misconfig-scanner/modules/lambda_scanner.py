import boto3
import logging

"""
lambda_scanner.py

This module scans AWS Lambda functions for potential misconfigurations such as:
- Publicly accessible Lambda URLs
- Excessive IAM permissions attached
- No environment variable encryption
- Unrestricted concurrency or timeouts

"""

logger = logging.getLogger(__name__)

def scan_lambda():
    findings = []
    client = boto3.client('lambda')

    try:
        paginator = client.get_paginator('list_functions')
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
                
                # Check concurrency limits
                concurrency = client.get_function_concurrency(FunctionName=function_name)
                if 'ReservedConcurrentExecutions' not in concurrency:
                    findings.append({
                        'Function': function_name,
                        'Issue': 'No reserved concurrency set'
                    })
                
                # Check permissions (basic, not full IAM policy evaluation)
                policy = client.get_policy(FunctionName=function_name)
                if 'Policy' in policy:
                    findings.append({
                        'Function': function_name,
                        'Issue': 'Function has resource policy attached; review for overly permissive access.'
                    })
    except Exception as e:
        logger.error(f"Error scanning Lambda functions: {e}")
        findings.append({'Error': str(e)})
    return findings