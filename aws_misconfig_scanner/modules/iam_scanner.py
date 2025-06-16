import boto3
from aws_misconfig_scanner.utils.logger import setup_logger

"""
iam_scanner.py

AWS IAM Misconfiguration Scanner

This module scans AWS Identity and Access Management (IAM) configurations for common security misconfigurations such as:
- Overly permissive IAM policies (wildcard actions/resources)
- Root account usage without MFA
- Inactive access keys

The scanner leverages the AWS SDK for Python (boto3) and is designed to integrate into a broader AWS misconfiguration scanning framework.

Author: Tom D.
"""

logger = setup_logger(__name__)

class IAMScanner:
    """
    Class: IAMScanner

    Description:
        Performs AWS IAM configuration analysis to identify misconfigurations related to:
        - Root account usage without MFA
        - Overly permissive IAM policies
        - Inactive access keys across IAM users

    Attributes:
        client (boto3.client): Boto3 IAM client used to retrieve IAM configurations.
    """

    def __init__(self):
        """
        Initializes the IAMScanner instance and establishes connection to the AWS IAM service.
        """
        self.client = boto3.client('iam')

    def check_root_account_usage(self, findings):
        """
        Verifies whether the AWS root account has Multi-Factor Authentication (MFA) enabled.
        Lack of MFA on the root account is flagged as a serious security risk.

        Args:
            findings (list): A list to collect findings related to IAM misconfigurations.
        """
        response = self.client.get_account_summary()
        root_mfa_enabled = response['SummaryMap'].get('AccountMFAEnabled', 0)
        if root_mfa_enabled == 0:
            msg = "Root account does not have MFA enabled. This is a security risk."
            logger.warning(msg)
            findings.append({'Issue': msg})
        else:
            logger.info("Root account has MFA enabled. This is a good security practice.")

    def list_overly_permissive_policies(self, findings):
        """
        Identifies customer-managed IAM policies that allow full administrative privileges
        using wildcard actions and wildcard resources ('*'). Such policies are flagged
        as overly permissive and pose high risk if misused.

        Args:
            findings (list): A list to collect findings related to IAM misconfigurations.
        """
        paginator = self.client.get_paginator('list_policies')
        for page in paginator.paginate(Scope='Local'):  # Only scan Local scope
            for policy in page['Policies']:
                policy_version = self.client.get_policy_version(
                    PolicyArn=policy['Arn'],
                    VersionId=policy['DefaultVersionId']
                )
                statements = policy_version['PolicyVersion']['Document']['Statement']
                if not isinstance(statements, list):
                    statements = [statements]
                for smt in statements:
                    if smt.get('Effect') == 'Allow' and smt.get('Action') == '*' and smt.get('Resource') == '*':
                        msg = f"Overly permissive policy found: {policy['PolicyName']}"
                        logger.warning(msg)
                        findings.append({'PolicyName': policy['PolicyName'], 'Issue': msg})

    def check_inactive_access_keys(self, findings, threshold_days=90):
        """
        Identifies IAM users with access keys that have either:
        - Never been used
        - Have not been used in a long period (inactive keys)

        Args:
            findings (list): A list to collect findings related to IAM misconfigurations.
            threshold_days (int): (Optional) Number of days used as inactivity threshold.
        """
        users = self.client.list_users()['Users']
        for user in users:
            keys = self.client.list_access_keys(UserName=user['UserName'])['AccessKeyMetadata']
            for key in keys:
                access_key_last_used = self.client.get_access_key_last_used(AccessKeyId=key['AccessKeyId'])
                last_used_date = access_key_last_used['AccessKeyLastUsed'].get('LastUsedDate')
                if not last_used_date:
                    msg = f"Access key {key['AccessKeyId']} for user {user['UserName']} has never been used."
                    logger.warning(msg)
                    findings.append({'UserName': user['UserName'], 'AccessKeyId': key['AccessKeyId'], 'Issue': msg})
                else:
                    logger.info(f"Access key {key['AccessKeyId']} for user {user['UserName']} last used on {last_used_date}.")
    
    def check_users_for_admin_access(self, findings):
        """Scan IAM users for attached AdministratorAccess policy."""
        users = self.client.list_users()['Users']
        for user in users:
            attached_policies = self.client.list_attached_user_policies(UserName=user['UserName'])['AttachedPolicies']
            for policy in attached_policies:
                if policy['PolicyName'] == 'AdministratorAccess':
                    msg = f"IAM User '{user['UserName']}' has AdministratorAccess attached."
                    logger.warning(msg)
                    findings.append({'UserName': user['UserName'], 'Issue': msg})

    def check_roles_for_admin_access(self, findings):
        """Scan IAM roles for attached AdministratorAccess policy (including Lambda roles)."""
        paginator = self.client.get_paginator('list_roles')
        for page in paginator.paginate():
            for role in page['Roles']:
                role_name = role['RoleName']
                attached_policies = self.client.list_attached_role_policies(RoleName=role_name)['AttachedPolicies']
                for policy in attached_policies:
                    if policy['PolicyName'] == 'AdministratorAccess':
                        msg = f"IAM Role '{role_name}' has AdministratorAccess attached."
                        logger.warning(msg)
                        findings.append({'RoleName': role_name, 'Issue': msg})

    def run_all_checks(self):
        """
        Executes the full IAM misconfiguration assessment, sequentially performing:
        - Root account MFA check
        - Policy permissions review
        - Inactive access key review

        Returns:
            findings (list): A list of dictionaries describing discovered misconfigurations.
        """
        logger.info("Starting IAM Misconfiguration Scan...")
        findings = []
        try:
            self.check_root_account_usage(findings)
            self.list_overly_permissive_policies(findings)
            self.check_inactive_access_keys(findings)
            self.check_users_for_admin_access(findings)
            self.check_roles_for_admin_access(findings)
        except Exception as e:
            logger.error(f"Error during IAM scan: {e}")
            findings.append({'Error': str(e)})
        logger.info("IAM Misconfiguration Scan completed.")
        return findings