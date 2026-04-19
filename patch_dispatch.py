path = r'c:\Users\Shao\Desktop\INT_Project\Code\CloudCompliancePlatform\backend\app\core\remediation.py'
with open(path, 'rb') as f:
    content = f.read().decode('utf-8')

# Fix _flag_iam_mfa -> _flag_iam_mfa_missing (correct method name)
old = '"_flag_iam_mfa",'
new = '"_flag_iam_mfa_missing",'
n = content.count(old)
content = content.replace(old, new)
print(f"Fixed _flag_iam_mfa references: {n}")

with open(path, 'w', encoding='utf-8', newline='') as f:
    f.write(content)
print("Done.")
