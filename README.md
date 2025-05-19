# Python Package Manager

## Overview

This repo is a self-usage python package manager to achieve some necessary function when do package management.

1. Filter out **base packages** from requirement package list, and generate human-readable csv format dependency tree for base packages.
2. Generate weekly report (created an action which triggered every 8 AM on Monday) which contains following information for all packages:
   1. Current version of package
   2. Type of package (base package or dependency package)
   3. All upgradable version of package
   4. Suggested version to upgrade to of a package
   5. Dependencies of current version
   6. Dependencies of newest version
   7. Vulnerabilities of current version
   8. Vulnerabilities of all upgradable version

## Usage

### Before run scripts

Need to pip install packages from `requirements.txt`

### Generate dependency tree for base packages

1. You will need to maintain a txt file called `requirements_full_list.txt`, which includes all packages that you freezed from your project (with version and all dependencies)
2. Run the script `CheckDependency.py`, it will:
   1. pip install all packages in `requirements_full_list.txt` (if installment failed, the script will skip those packages)
   2. use pipdeptree to output json format dependency tree
   3. extract base packages and its dependencies from json to `BasePackageWithDependencies.csv`

### Generate upgrade and vulnerabilities report for all packages

1. To let script tag base package or dependency package, you will need to run `CheckDependency.py` as the instruction above
2. Modify the .env file if you want
3. Run the script `GenerateWeeklyReport.py`, it will:
   1. Fetch packages list in `requirements_full_list.txt` (no need to pip install packages) and `BasePackageWithDependencies.csv` to tag base/dependency package
   2. Run pip audit to fetch upgradeable versions.
   3. Scan vulnerabilities via osv for current version and upgradeable versions
   4. Generate report in csv, html and json format

### .env

`GenerateWeeklyReport` will read .env file that stores some basic configs:

1. `FULL_RELOAD_PACKAGES=False`: it controls whether the workflow will trigger the `CheckDependency.py`, by right we should not change this flag to `True` unless we add some packages into `requirements_full_load.txt`.
2. `BASE_PACKAGE_TXT=base_package_list.txt`: it states the base package list, regarding to step 1 above, you can change to other txt files if you already have the base package list. You can either choose to upload/generate a txt or csv file.
3. `BASE_PACKAGE_CSV=BasePackageWithDependencies.csv`: it states the base package list, regarding to step 1 above, you can change to other csv files if you already have the base package list. You can either choose to upload/generate a txt or csv file.
4. `CHECK_DEPENDENCY_SCRIPT=CheckDependency.py`: it stats the script name of checking dependencies.
5. `REQUIREMENTS_FILE=requirements_full_list.txt`: it stats the txt file that contains all packages and versions you need to include in the report.
6. `PIP_AUDIT_CMD=pip-audit --format json`: it stats the pip audit command, you can change the command using other packages to scan, just need to ensure the output format is json.
7. `PYPI_URL_TEMPLATE=https://pypi.org/pypi/{package}/json`: it stats the website that fetch upgradeable versions, you can change to other website, just need to ensure the output format is json.
8. `SEMAPHORE_NUMBER=3`: it controls the semaphore number when fetching data from pypi, high semahore number may cause anti-flood from pypi.
