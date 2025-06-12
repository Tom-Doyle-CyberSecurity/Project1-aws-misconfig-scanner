import boto3

"""
Scan AWS EC2 instances for public IP misconfigurations.

    This function connects to the EC2 service using Boto3, retrieves all EC2 instances
    across all reservations, and checks whether each instance has a public IP address assigned.
    Publicly accessible instances are flagged as potential security risks.

    Misconfiguration Detected:
    - EC2 instances with a public IP address may expose services directly to the internet,
      which increases attack surface if security groups or OS hardening are weak.

"""

def scan_ec2_instances():

    # Initialize the EC2 client
    ec2 = boto3.client('ec2')

    # Retrive all EC2 instances
    instances = ec2.describe_instances()

    # Loop through each reservation and instance
    for reservation in instances['Reservations']:

        # Loop through instancees inside each reservation
        for instance in reservation['Instances']:
            instance_id = instance['InstanceId']
            print(f"\nChecking EC2 instance: {instance_id}")

            # Retrive public IP address if assigned
            public_ip = instance.get('PublicIpAddress')

            if public_ip:
                # Public IP detected - flag as misconfiguration
                print(f"[!] Instance {instance_id} has a public IP assigned: {public_ip}")
            else:
                # No public IP assigned - instance not publicly reachable
                print(f"[-] Instance {instance_id} has no public IP assigned.")