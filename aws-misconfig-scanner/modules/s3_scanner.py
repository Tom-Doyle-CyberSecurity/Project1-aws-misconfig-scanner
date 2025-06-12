import boto3
import json
from botocore.exceptions import ClientError

def scan_s3_buckets():
    s3 = boto3.client('s3')
    buckets = s3.list_buckets()['Buckets']

    for bucket in buckets:
        bucket_name = bucket['Name']
        print(f"\nChecking bucket: {bucket_name}")

        # ACL check
        acl = s3.get_bucket_acl(Bucket=bucket_name)
        for grant in acl['Grants']:
            if 'AllUsers' in str(grant('Grantee')):
                print(f"[!] Bucket {bucket_name} is publicly accessible via ACL.")

        # Bucket policy check
        try:
            policy = s3.get_bucket_policy(Bucket=bucket_name)
            if '"Principal":"*"' in policy['Policy']:
                print(f"[!] Bucket {bucket_name} is public via policy.")
        except s3.exceptions.ClientError:
            pass

        # Encryption check
        try: 
            encryption = s3.get_bucket_encryption(Bucket=bucket_name)
        except s3.exceptions.ClientError:
            print(f"[!] Bucket {bucket_name} has no default encryption.")
        
        # Versioning check
        versioning = s3.get_bucket_versioning(Bucket=bucket_name)
        if versioning.get('Status') != 'Enabled':
            print(f"[!] Bucket {bucket_name} has versioning disabled")

