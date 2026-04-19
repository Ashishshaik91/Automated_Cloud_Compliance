import os, glob, re

for f in glob.glob(r'c:\Users\Shao\Desktop\INT_Project\Code\CloudCompliancePlatform\backend\policies\**\*.yaml', recursive=True):
    with open(f, 'r') as fp:
        content = fp.read()
    
    # Change all opa_package to generic
    content = re.sub(r'opa_package:\s*["\']?compliance\.[a-zA-Z0-9_]+\.[a-zA-Z0-9_]+["\']?', 'opa_package: "compliance.generic"', content)
    
    # Fix cis-iam-no-active-keys: change not_equals 0 to equals 0
    if 'cis-iam-no-active-keys' in content:
        content = content.replace('operator: "not_equals"', 'operator: "equals"')
    
    with open(f, 'w') as fp:
        fp.write(content)

print("Fixed YAML files.")
