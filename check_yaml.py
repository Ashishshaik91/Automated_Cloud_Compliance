import glob, yaml

for f in glob.glob(r'c:\Users\Shao\Desktop\INT_Project\Code\CloudCompliancePlatform\backend\policies\**\*.yaml', recursive=True):
    with open(f, 'r') as fp:
        data = yaml.safe_load(fp)
    for p in data.get('policies', []):
        if p.get('resource_type') == 'cloudtrail':
            print(f"{p['id']}: {p.get('rules')}")
