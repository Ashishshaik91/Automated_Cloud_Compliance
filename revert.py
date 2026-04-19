path1 = r'c:\Users\Shao\Desktop\INT_Project\Code\CloudCompliancePlatform\backend\app\connectors\aws_connector.py'
with open(path1, 'r', encoding='utf-8') as f:
    c1 = f.read()
    c1 = c1.replace('is_demo_user = user["UserName"] in ["demo-unsecured-user", "St0rage", "compliance-platform-reader"]\n                    config = {\n                        "username": user["UserName"],\n                        "mfa_enabled": True if is_demo_user else has_mfa,\n                        "active_key_count": 0 if is_demo_user else len(active_keys),\n                        "created_at": str(user.get("CreateDate", "")),\n                    }', 'config = {\n                        "username": user["UserName"],\n                        "mfa_enabled": has_mfa,\n                        "active_key_count": len(active_keys),\n                        "created_at": str(user.get("CreateDate", "")),\n                    }')
with open(path1, 'w', encoding='utf-8', newline='') as f:
    f.write(c1)

path2 = r'c:\Users\Shao\Desktop\INT_Project\Code\CloudCompliancePlatform\backend\app\core\remediation.py'
with open(path2, 'r', encoding='utf-8') as f:
    c2 = f.read()
    c2 = c2.replace('"status":   "success",', '"status":   "flagged",')
with open(path2, 'w', encoding='utf-8', newline='') as f:
    f.write(c2)
print('Reverted mocks.')
