import re
import pkg_resources
import subprocess
import json
import pandas as pd

requirements_file = "/workspaces/mend_scan_template/requirements_full_list.txt"
# Step 1: Load base package list and save original line
base_packages = {}  # {pkg_key: original_line}
with open(requirements_file) as f:
    for line in f:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        pkg_name = re.split(r"[<>=!~]+", line)[0]
        try:
            pkg_key = pkg_resources.Requirement.parse(pkg_name).key
        except Exception:
            pkg_key = pkg_name.lower()
        base_packages[pkg_key] = line 

# Step 2: Install all packages one by one (ignore dependency conflicts, skip failures)
for pkg_key, pkg_line in base_packages.items():
    print(f"⬇️ Installing: {pkg_line}")
    result = subprocess.run([
        "pip", "install", "--no-deps", "--ignore-installed", pkg_line
    ], capture_output=True, text=True)
    if result.returncode != 0:
        print(f"⚠️ Failed to install {pkg_line}. Skipping.\nError: {result.stderr}")
    else:
        print(f"✅ Installed: {pkg_line}")

# Step 3: Ensure pipdeptree is installed
subprocess.run(["pip", "install", "--quiet", "pipdeptree"], check=True)

# Step 4: Get the full dependency tree as JSON
result = subprocess.run(["pipdeptree", "--json", "--all"], capture_output=True, text=True)
data = json.loads(result.stdout)

# Step 5: Build a map: {parent_pkg: [dep_name, dep_name, ...]}
tree_map = {}
pkg_versions = {}
all_dependencies_set = set() 

for item in data:
    parent = item["package"]["key"]
    parent_version = item["package"]["installed_version"]
    pkg_versions[parent] = parent_version
    deps = []
    for dep in item.get("dependencies", []):
        dep_name = dep["key"]
        deps.append(dep_name)
        all_dependencies_set.add(dep_name)  
    tree_map[parent] = deps

# Recursive dependency collector
def get_all_dependencies(pkg_key, tree_map, visited=None):
    if visited is None:
        visited = set()
    if pkg_key in visited:
        return []
    visited.add(pkg_key)

    deps = []
    for dep in tree_map.get(pkg_key, []):
        deps.append(dep)
        deps.extend(get_all_dependencies(dep, tree_map, visited))
    return deps

# Step 6: Filter base packages that are not depended by others
all_depended_packages = set()
for deps in tree_map.values():
    all_depended_packages.update(deps)

# Only keep base packages that are not depended by others
pure_base_packages = [pkg for pkg in base_packages if pkg not in all_depended_packages]

# Collect full dependencies for each remaining pure base package (no version info)
rows = []
for base in pure_base_packages:
    full_deps = get_all_dependencies(base, tree_map)
    unique_deps = sorted(set(full_deps))
    row = {
        "Base Package": base,
    }
    for idx, dep in enumerate(unique_deps, start=1):
        row[f"dependsBy{idx}"] = dep
    rows.append(row)

# Step 7: Save to CSV
df = pd.DataFrame(rows)
df.to_csv("TRM_base_packages_with_dependencies.csv", index=False)
print("✅ Exported to TRM_base_packages_with_dependencies.csv")
print(df)
