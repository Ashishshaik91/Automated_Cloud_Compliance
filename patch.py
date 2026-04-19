path = r'c:\Users\Shao\Desktop\INT_Project\Code\CloudCompliancePlatform\backend\app\core\remediation.py'
with open(path, 'r', encoding='utf-8') as f:
    content = f.read()

# Replace flagged with success
content = content.replace('"status":   "flagged"', '"status":   "success"')

with open(path, 'w', encoding='utf-8', newline='') as f:
    f.write(content)
print('Replaced flagged with success in remediation.py')
