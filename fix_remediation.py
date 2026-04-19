path = r'c:\Users\Shao\Desktop\INT_Project\Code\CloudCompliancePlatform\backend\app\core\remediation.py'

with open(path, 'rb') as f:
    raw = f.read()

text = raw.decode('utf-8', errors='replace')

# Find and replace the problematic block
old_crlf = (
    "        # Build a minimal synthetic check so handler signatures work unchanged\r\n"
    "        check = ComplianceCheck.__new__(ComplianceCheck)\r\n"
    "        check.policy_id    = rule_id\r\n"
    "        check.resource_id  = resource_id\r\n"
    '        check.resource_type = ""\r\n'
)
old_lf = old_crlf.replace('\r\n', '\n')

new_block = (
    "        # Use SimpleNamespace to avoid SQLAlchemy ORM init errors\r\n"
    "        import types\r\n"
    "        check = types.SimpleNamespace(\r\n"
    "            policy_id=rule_id,\r\n"
    "            resource_id=resource_id,\r\n"
    '            resource_type="",\r\n'
    "        )\r\n"
)

replaced = text.replace(old_crlf, new_block)
if replaced == text:
    replaced = text.replace(old_lf, new_block.replace('\r\n', '\n'))

if replaced == text:
    print("NO MATCH — searching for key line:")
    for i, line in enumerate(text.splitlines()):
        if 'ComplianceCheck.__new__' in line or 'minimal synthetic' in line or 'resource_type' in line:
            print(f"  L{i+1}: {repr(line)}")
else:
    with open(path, 'wb') as f:
        f.write(replaced.encode('utf-8'))
    print("FIXED OK")
