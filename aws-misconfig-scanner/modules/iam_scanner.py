import boto3
import logging
from utils.logger import setup_logger

"""
iam_scanner.py

AWS IAM Misconfiguration Scanner

This module scans AWS Identity and Access Management (IAM) configurations for common security misconfigurations, such as overly permissive policies, root account usage, and inactive credentials.

Author: Tom D.
"""
logger = setup_logger(__name__)

# Class to to scan AWS IAM configurations for potential security risks
class IAMScanner:
    def __init__(self):
        # Initialise the IAM client
        self.client = boto3.client('iam')
    def check_root_account_usage(self):

        # Check if AWS root account has been used recently
        response = self.client.get_account_summary()
        root_mfa_enabled = response['SummaryMap'].get('AccountMFAEnabled', 0)
        if root_mfa_enabled == 0:
            logging.warning("Root account does not have MFA enabled. This is a security risk.")
        else:
            logging.info("Root account has MFA enabled. This is a good security practice.")
    def list_ovrerly_permissive_policies(self):

        # Identify policies that allow widldcard permissions
        paginator = self.client.get_paginator('list_policies')
        for page in paginator.paginate(Scope = 'local'):
            for policy in page['Policies']:
                policy_version = self.client.get_policy_version(
                    PolicyArn = policy['Arn'],
                    VersionId = policy['DefaultVersionId']
                )
                statements = policy_version['PolicyVersion']['Document']['Statement']
                if not isinstance(statements, list):
                    statements = [statements]
                for smt in statements:
                    if smt.get('Effect') == 'Allow' and stmt.get('Action') == '*' and stmt.get('Resource') == '*':
                        logging.warning(f"Overly permissive policy found: {policy['PolicyName']})")
    # Identify users with inactive keys beyond threshold
    def check_inactive_access_keys(self, threshold_days=90):
        users = self.client.list_users()['Users']
        for user in users:
            keys = self.client.list_access_keys(UserName=user['UserName'])['AccessKeyMetadata']
            for key in keys:
                access_key_last_used = self.client.get_access_key_last_used(AccessKeyId=key['AccessKeyId'])
                last_used_date = last_used['AccessKeyLastUsed'].get('LastUsedDate')
                if not last_used_date:
                    logger.warning(f"Access key {key['AccessKeyId']} for user {user['UserName']} has never been used.")
                else:
                    logger.info(f"Access key {key['AccessKeyId']} for user {user['UserName']} last used on {last_used_date}.")
    # Execut all IAM security checks
    def run_all_checks(self):
        logger.info("Starting IAM Misconfiguration Scan...")
        self.check_root_account_usag()
        self.list_ovrly_permissive_policies()
        self.check_inactive_access_keys()
        logger.info("IAM Misconfiguration Scan completed.")
        
    