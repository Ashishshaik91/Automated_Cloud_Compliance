import os
import sys
import time
import datetime
import boto3
import pyotp

def enable_mfa(username):
    iam = boto3.client('iam', region_name='us-east-1')
    
    # Check if MFA already exists
    mfa_devices = iam.list_mfa_devices(UserName=username)
    if len(mfa_devices.get('MFADevices', [])) > 0:
        print(f"MFA already enabled for {username}")
        return

    account_id = boto3.client('sts').get_caller_identity().get('Account')
    serial_number = f"arn:aws:iam::{account_id}:mfa/{username}-demo-mfa"
    
    # Delete any existing unassigned virtual MFA device with the same name to avoid conflicts
    try:
        iam.delete_virtual_mfa_device(SerialNumber=serial_number)
    except Exception:
        pass
        
    print(f"Creating virtual MFA device for {username}...")
    response = iam.create_virtual_mfa_device(
        VirtualMFADeviceName=f"{username}-demo-mfa"
    )
    serial_number = response['VirtualMFADevice']['SerialNumber']
    seed = b''.join(response['VirtualMFADevice']['Base32StringSeed']).decode('utf-8') if isinstance(response['VirtualMFADevice']['Base32StringSeed'], list) else response['VirtualMFADevice']['Base32StringSeed'].decode('utf-8') if isinstance(response['VirtualMFADevice']['Base32StringSeed'], bytes) else response['VirtualMFADevice']['Base32StringSeed']
    
    # Generate 2 consecutive OTPs
    totp = pyotp.TOTP(seed)
    
    # Get current time
    now = datetime.datetime.now()
    # Code 1
    code1 = totp.at(now)
    # Code 2 (must be consecutive, so +30 seconds)
    code2 = totp.at(now + datetime.timedelta(seconds=30))
    
    print(f"Enabling MFA for {username} with codes {code1}, {code2}...")
    iam.enable_mfa_device(
        UserName=username,
        SerialNumber=serial_number,
        AuthenticationCode1=code1,
        AuthenticationCode2=code2
    )
    print(f"Success: MFA enabled for {username}")

if __name__ == '__main__':
    users = ["demo-unsecured-user", "St0rage", "compliance-platform-reader"]
    for u in users:
        try:
            enable_mfa(u)
        except Exception as e:
            print(f"Error enabling MFA for {u}: {e}")
