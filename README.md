# Python Package Manager

## Introduction

This repository provides a Python-based package management and reporting tool for self-use. It helps you manage dependencies, track vulnerabilities, and generate upgrade recommendations for your Python projects. The tool can filter out base packages, generate a dependency tree, and produce weekly reports in CSV, HTML, and JSON formats.

---

## Function Overview

- **Dependency Tree Generation:**  
  Filter out **base packages** from your requirements and generate a human-readable CSV dependency tree for base packages.

- **Weekly Report Generation:**  
  Generate a weekly report containing:
  - Current version of each package
  - Package type (base or dependency)
  - All upgradable versions
  - Suggested upgrade version
  - Dependencies for current and latest versions
  - Vulnerabilities for current and all upgradable versions

- **Vulnerability Scanning:**  
  Integrates with `pip-audit` and OSV to check for known vulnerabilities in your dependencies.

- **Upgrade Suggestions:**  
  Suggests safe minor upgrades and provides upgrade instructions, including compatible dependency versions.

---

## Usage

### 1. Install Dependencies

Install required packages from `requirements.txt`:

```sh
pip install -r requirements.txt
```

---

### 2. Generate Dependency Tree for Base Packages

1. Maintain a file `src/requirements_full_list.txt` listing all packages (with versions) you want to manage.
2. Run the script to extract the dependency tree:

   ```sh
   python utils/CheckDependency.py
   ```

   This will:
   - Install all packages from `requirements_full_list.txt` (skipping any that fail)
   - Use `pipdeptree` to output a JSON dependency tree
   - Extract base packages and their dependencies to `src/BasePackageWithDependencies.csv`

---

### 3. Generate Upgrade and Vulnerabilities Report

1. Ensure you have run `CheckDependency.py` as above to tag base and dependency packages.
2. (Optional) Edit the `.env` file to customize paths and settings (see below).
3. Run the report generation script:

   ```sh
   python GenerateReport.py --output all
   ```

   This will:
   - Read package lists from `src/requirements_full_list.txt` and `src/BasePackageWithDependencies.csv`
   - Run pip audit to fetch upgradable versions
   - Scan vulnerabilities via OSV for current and upgradable versions
   - Generate reports in CSV, HTML, and JSON formats in the `WeeklyReport` folder

---

### 4. .env File Usage

The `.env` file stores configuration for the workflow. Key settings include:

- `FULL_RELOAD_PACKAGES=False`: Controls whether to re-run dependency extraction. Set to `True` only if you update `requirements_full_list.txt`.
- `BASE_PACKAGE_TXT=src/base_package_list.txt`: Path to the base package list (TXT).
- `BASE_PACKAGE_CSV=src/BasePackageWithDependencies.csv`: Path to the base package list (CSV).
- `CHECK_DEPENDENCY_SCRIPT=utils/CheckDependency.py`: Script for dependency extraction.
- `REQUIREMENTS_FILE=src/requirements_full_list.txt`: Path to the full requirements file.
- `CUSTODIAN_LIST=src/custodian.csv`: Path to the custodian mapping file.
- `NOTUSED_PACKAGES=src/NotUsed.txt`: Path to the NotUsed packages file.
- `PIP_AUDIT_CMD=pip-audit --format json`: Command for vulnerability scanning.
- `PYPI_URL_TEMPLATE=https://pypi.org/pypi/{package}/json`: URL template for fetching PyPI metadata.
- `SEMAPHORE_NUMBER=3`: Controls concurrency when fetching data from PyPI (higher values may trigger anti-flood protection).

---

## Output

- Reports are saved in the `WeeklyReport/YYYY-MM-DD/` directory.
- Formats: CSV, HTML, JSON.
- Failed package versions (if any) are listed in a separate file.

---

## Folder Structure

```
src/
  requirements_full_list.txt
  base_package_list.txt
  BasePackageWithDependencies.csv
  NotUsed.txt
  custodian.csv
utils/
  CheckDependency.py
  ...
templates/
  weekly_report.html.j2
WeeklyReport/
  YYYY-MM-DD/ <- Folder naming is weekly based (e.g. only generate Monday's date for whole week's report folder)
    report.csv
    report.html
    report.json
```

---

## Notes

- The tool is intended for self-use and internal reporting.
- You can further customize the scripts and templates as needed for your workflow.
