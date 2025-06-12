import boto3
import json
from botocore.exceptions import ClientError

"""
Scan AWS S3 buckets for misconfigurations.

    This function connects to the S3 service using Boto3, retrieves all buckets in the account,
    and evaluates multiple configuration aspects to identify public access risks.

    Misconfiguration Checks Performed:
    - ACL Check: Verifies if the bucket grants public access via Access Control Lists (ACLs).
    - Bucket Policy Check: Verifies if the bucket policy allows open access to all principals (*).
    - Encryption Check: Checks if default encryption is enabled for the bucket.
    - Versioning Check: Checks if versioning is enabled for data protection and recovery.

    Security Context:
    - Publicly accessible S3 buckets can expose sensitive data directly to the internet.
    - Lack of encryption increases the risk of plaintext data exposure if compromised.
    - Versioning improves data durability and protection against accidental deletions.
"""

def scan_s3_buckets():

    # Initialize the S3 client
    s3 = boto3.client('s3')

    # Retrieve all S3 buckets in the account
    buckets = s3.list_buckets()['Buckets']

    for bucket in buckets:
        bucket_name = bucket['Name']
        print(f"\nChecking bucket: {bucket_name}")

        # ACL check: Check for 'AllUsers' grants (public access)
        acl = s3.get_bucket_acl(Bucket=bucket_name)
        for grant in acl['Grants']:
            if 'AllUsers' in str(grant('Grantee')):
                print(f"[!] Bucket {bucket_name} is publicly accessible via ACL.")

        # Bucket policy Check: Check for public '*' principals in the bucket policy
        try:
            policy = s3.get_bucket_policy(Bucket=bucket_name)
            if '"Principal":"*"' in policy['Policy']:
                print(f"[!] Bucket {bucket_name} is public via policy.")
        except s3.exceptions.ClientError:
            pass # No policy attached to bucket (normal case)

        # Encryption check: Verify if default encryption is enabled
        try: 
            encryption = s3.get_bucket_encryption(Bucket=bucket_name)
        except s3.exceptions.ClientError:
            print(f"[!] Bucket {bucket_name} has no default encryption.")
        
        # Versioning Check: Verify if versioning is enabled
        versioning = s3.get_bucket_versioning(Bucket=bucket_name)
        if versioning.get('Status') != 'Enabled':
            print(f"[!] Bucket {bucket_name} has versioning disabled")

