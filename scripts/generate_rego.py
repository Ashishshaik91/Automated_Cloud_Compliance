# Dev utility — converts YAML compliance policies to OPA Rego stubs.
# Run manually: python scripts/generate_rego.py
import yaml
from pathlib import Path

yaml_dir = Path("backend/policies")
opa_dir = Path("opa/policies")

for yaml_file in yaml_dir.glob("*/*.yaml"):
    with open(yaml_file, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
        
    framework = yaml_file.parent.name
    
    # Group by resource type
    packages = {}
    for policy in data.get("policies", []):
        pkg = policy.get("opa_package")
        if not pkg: continue
        
        resource_type = policy.get("resource_type")
        if pkg not in packages:
            packages[pkg] = []
        packages[pkg].append(policy)
        
    for pkg, policies in packages.items():
        # e.g. compliance.soc2.iam
        parts = pkg.split(".")
        filename = opa_dir / f"{parts[1]}_{parts[2]}.rego"
        
        # We don't want to overwrite generic or pci_dss_s3 as they already exist
        if filename.name == "pci_dss_s3.rego":
            continue
            
        with open(filename, "w", encoding="utf-8") as out:
            out.write(f"# OPA Rego Policy {parts[1].upper()} {parts[2].upper()} Checks\n")
            out.write(f"package {pkg}\n\n")
            out.write("import rego.v1\n\n")
            out.write("default allow := false\n\n")
            
            # Generate allow condition
            allow_conditions = []
            for pol in policies:
                for rule in pol.get("rules", []):
                    field = rule.get("field")
                    op = rule.get("operator")
                    if op == "is_true":
                        allow_conditions.append(f"input.resource.{field} == true")
                    elif op == "is_false":
                        allow_conditions.append(f"input.resource.{field} == false")
                        
            out.write("allow if {\n")
            for cond in set(allow_conditions):
                out.write(f"    {cond}\n")
            out.write("}\n\n")
            
            # Generate deny conditions
            for pol in policies:
                for rule in pol.get("rules", []):
                    field = rule.get("field")
                    op = rule.get("operator")
                    
                    out.write("deny contains reason if {\n")
                    if op == "is_true":
                        out.write(f"    not input.resource.{field}\n")
                        out.write(f"    reason := \"{pol['name']} failed\"\n")
                    elif op == "is_false":
                        out.write(f"    input.resource.{field}\n")
                        out.write(f"    reason := \"{pol['name']} failed\"\n")
                    out.write("}\n\n")
                
print("Generated OPA rego policies.")
