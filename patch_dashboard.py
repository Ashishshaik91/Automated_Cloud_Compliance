path = r'c:\Users\Shao\Desktop\INT_Project\Code\CloudCompliancePlatform\frontend\src\pages\Dashboard.jsx'
with open(path, 'rb') as f:
    content = f.read().decode('utf-8')

# Fix onSubmitted to also refresh summary + checks
old = "onSubmitted={() => { fetchViolationsDspm(); setRemediateTarget(null) }}"
new = "onSubmitted={() => { fetchViolationsDspm(); fetchData(); setRemediateTarget(null) }}"

n = content.count(old)
content = content.replace(old, new)
print(f"onSubmitted replacements: {n}")

with open(path, 'w', encoding='utf-8', newline='') as f:
    f.write(content)
print("Done.")
