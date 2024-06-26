[![Logo](https://mend-toolkit-resources-public.s3.amazonaws.com/img/mend-io-logo-horizontal.svg)](https://www.mend.io/)  
[![License](https://img.shields.io/badge/License-Apache%202.0-yellowgreen.svg)](https://opensource.org/licenses/Apache-2.0)
[![Mend projects cleanup](https://github.com/whitesource-ps/ws-cleanup-tool/actions/workflows/ci.yml/badge.svg)](https://github.com/whitesource-ps/ws-cleanup-tool/actions/workflows/ci.yml)
[![Python 3.6](https://upload.wikimedia.org/wikipedia/commons/thumb/8/8c/Blue_Python_3.6%2B_Shield_Badge.svg/86px-Blue_Python_3.6%2B_Shield_Badge.svg.png)](https://www.python.org/downloads/release/python-360/)
[![PyPI](https://img.shields.io/pypi/v/ws-cleanup-tool?style=plastic)](https://pypi.org/project/ws-cleanup-tool/)

# Mend SCA Projects Cleanup CLI Tool
> [!WARNING]  
> The following project was created for, and should be used with the Legacy Mend User Interface. The Mend Unified Platform and Cloud Native creates empty projects on the Legacy Mend User Interface to store SAST and Cloud Native scans. Removing those projects could result in broken scans and information not being published to Mend correctly. If you are using Cloud Native or the Mend Unified Platform - It is recommended to run this tool in Dry Run mode and verify the projects to be deleted do not have SAST or Cloud Native scans prior to deletion.  

* The self-hosted CLI tool features cleaning up projects and generating reports before deletion in 2 modes:
  * By stating _OperationMode=FilterProjectsByUpdateTime_ and how many days to keep (-r/ DaysToKeep=)
  * By stating _OperationMode=FilterProjectsByLastCreatedCopies_ and how many copies to keep (-r/ DaysToKeep=)
* The reports are saved in the designated location as follows: _[Output_DIR]/[PRODUCT NAME]/[PROJECT NAME]/[REPORT NAME]_  
  * The default location is the _[WORKING DIRECTORY]/Mend/Reports/[PRODUCT NAME]/[PROJECT NAME]/[REPORT NAME]_
* To review the outcome before actual deletion use _-y true_ / _DryRun=True_ flag. It will _NOT_ delete any project nor create reports 
* By default, the tool generates all possible project-level reports. By specifying ((_-t_ / _Reports=_/) it is possible to select specific reports
  * The full list of available reports is below
* The full parameters list is available below
* There are two ways to configure the tool:
  * By configuring _params.config_ on the executed dir or passing a path to the file in the same format
  * By setting command line parameters as specified in the usage below
  
## Supported Operating Systems
- **Linux (Bash):**	CentOS, Debian, Ubuntu, RedHat
- **Windows (PowerShell):**	10, 2012, 2016

## Pre-requisites 
* Python 3.8+

## Permissions
* The user used to execute the tool has to have "Organization Administrator" or "Product Administrator" on all the maintained products and "Organization Auditor" permissions. 
* It is recommended to use a service user.

## Installation and Execution from PyPi (recommended):
1. Install by executing: `pip install mend-sca-cleanup-tool`
2. Configure the appropriate parameters either by using the command line or in `params.config`.
3. Execute the tool (`mend_sca_cleanup_tool ...`).
4. In order to update the tool please run `pip install mend-sca-cleanup-tool --upgrade`

## Installation and Execution from GitHub:
1. Download and unzip **mend-sca-cleanup-tool.zip** from the most recent tagged release.
2. Install requirements: `pip install -r requirements.txt`
3. Configure the appropriate parameters either by using the command line or `params.config`.
4. Execute: `python sca_cleanup_tool.py <CONFIG_FILE>` 

## Examples:
Perform dry run check-in to get to know which projects would have been deleted:  
`mend_sca_cleanup_tool -r 30 -m FilterProjectsByUpdateTime -u <USER_KEY> -k <ORG_TOKEN> -y true`

---

Keep the last 60 days on each product, omitting a product token <PRODUCT_1> from analyzing:  
`mend_sca_cleanup_tool -r 60 -m FilterProjectsByUpdateTime -u <USER_KEY> -k <ORG_TOKEN> -e <PRODUCT_TOKEN_1>`

---

Keep only two of the newest projects in each product token PRODUCT_1 and PRODUCT_2:  
`mend_sca_cleanup_tool -r 2 -m FilterProjectsByLastCreatedCopies -u <USER_KEY> -k <ORG_TOKEN> -i <PRODUCT_TOKEN_1>,<PRODUCT_TOKEN_2>`

---

Analyze only the projects that have the specified Mend tag and keep the newest project in each product:  
`mend_sca_cleanup_tool -r 1 -m FilterProjectsByLastCreatedCopies -u <USER_KEY> -k <ORG_TOKEN> -g <KEY>:<VALUE>`

---

Keep the last 2 weeks and analyze only the projects whose match their tag key and the tag value contains the specified value:  
`mend_sca_cleanup_tool -r 14 -m FilterProjectsByUpdateTime -u <USER_KEY> -k <ORG_TOKEN> -v <KEY>:<VALUE>`

---

Keep the last 100 days for both PRODUCT_1 and PRODUCT_2, but do not delete the project PROJECT_1 (which is a project in one of the included products):  
`mend_sca_cleanup_tool -r 100 -m FilterProjectsByUpdateTime -u <USER_KEY> -k <ORG_TOKEN> -i <PRODUCT_TOKEN_1>,<PRODUCT_TOKEN_2> -x <PROJECT_TOKEN_1>`

---

Keep the last month for both PRODUCT_1 and PRODUCT_2, but do not delete projects that contain provided strings in their names:  
`mend_sca_cleanup_tool -r 31 -m FilterProjectsByUpdateTime -u <USER_KEY> -k <ORG_TOKEN> -i <PRODUCT_TOKEN_1>,<PRODUCT_TOKEN_2> -n CI_,-test`

---

## Removing >5k Projects
If attempting to a large amount of the projects, the following configuraiton is recommended:
 `mend_sca_cleanup_tool -r 5 -m FilterProjectsByLastCreatedCopies -u <USER_KEY> -k <ORG_TOKEN> -ss true -s true`
 This configuration will keep the last 5 projects in any given product, skip report generation and the summary at the end of script execution. If you wish to generate reports, it is recommended to do so for 1 product at a time using the -i parameter.

## Full Usage flags:
```shell
usage: mend_sca_cleanup_tool [-h] -u MEND_USER_KEY -k MEND_TOKEN [-a MEND_URL] [-t REPORT_TYPES] [-m {FilterProjectsByUpdateTime,FilterProjectsByLastCreatedCopies}] [-o OUTPUT_DIR] [-e EXCLUDED_PRODUCT_TOKENS] [-i INCLUDED_PRODUCT_TOKENS]
                    [-g ANALYZED_PROJECT_TAG] [-r DAYS_TO_KEEP] [-p PROJECT_PARALLELISM_LEVEL] [-y DRY_RUN] [-pr ProxyUrl]

Mend Cleanup Tool

optional arguments:
  -h, --help            show this help message and exit
  -u MEND_USER_KEY, --userKey 
                    Mend User Key
  -k MEND_API_TOKEN, --apiToken, --orgToken
                    Mend Organization Key (API Key)
  -a MEND_URL, --mendUrl, --wsURL
                    Mend URL. This value defaults to saas.whitesourcesoftware.com.
  -t REPORT_TYPES, --reportTypes
                    Report Types to generate (comma seperated list)
  -m OPERATION_MODE, --operationMode {FilterProjectsByUpdateTime,FilterProjectsByLastCreatedCopies}
                    Cleanup operation mode
  -o OUTPUT_DIR, --outputDir
                    Output directory
  -e EXCLUDED_PRODUCT_TOKENS, --excludedProductTokens
                    List of excluded products
  -i INCLUDED_PRODUCT_TOKENS, --includedProductTokens
                    List of included products
  -g ANALYZED_PROJECT_TAG, --AnalyzedProjectTag
                    Analyze only the projects whose contain the specific Mend tag (key:value). Case sensitive.
  -v ANALYZED_PROJECT_TAG_REGEX_IN_VALUE, --AnalyzedProjectTagRegexInValue
                    Analyze only the projects whose match their tag key and the tag value contains the specified value (key:value). Case sensitive.
                    Note: This was originally broken in the original ws-cleanup-tool. The functionality was adjusted to work as originally written. The naming convention is a misnomer but was kept to avoid breaking existing integrations.
  -r DAYS_TO_KEEP, --DaysToKeep
                    Number of days to keep in FilterProjectsByUpdateTime or number of copies in FilterProjectsByLastCreatedCopies
  -p PROJECT_PARALLELISM_LEVEL, --ProjectParallelismLevel
                    Maximum number of threads to run
  -y DRY_RUN, --DryRun
                    Logging the projects that are supposed to be deleted without deleting and creating reports
                    default False
  -s SKIP_REPORT_GENERATION, --SkipReportGeneration
                    Skip report generation step
                    default False
  -j SKIP_PROJECT_DELETION, --SkipProjectDeletion
                    Skip project deletion step
                    default False                                        
  -x EXCLUDED_PROJECT_TOKENS, --excludedProjectTokens
                    List of excluded projects
  -n EXCLUDED_PROJECT_NAME_PATTERNS, --excludedProjectNamePatterns
                    List of excluded project name patterns (comma seperated list). Case sensitive.    
  -pr ProxyUrl, --proxy
                    The proxy URL. It should be provided in a format like this: < proxy_ip>:<proxy_port>.
                    In case of a proxy requires Basic Authentication 
                    the format should be like this <proxy_username>:<proxy_password>@<proxy_ip>:<proxy_port>.
                    If http:// or https:// prefix is not provided, the prefix http:// will be used by default.
  -ss SkipSummary, --SkipSummary
					Skips the summary of deleted projects at the end of report.
					Recommended if processing a lot of projects.
                          
```

## Available reports
The following Mend project reports are available through the clean-up tool. These values can be specified with the -t flag to generate specific reports.
* alerts
* alerts_rejected_by_policy
* attribution
* bugs
* due_diligence
* ignored_alerts
* in_house_libraries
* inventory
* license_compatibility
* resolved_alerts
* request_history
* source_files
* source_file_inventory
* vulnerability

## SAST Clean up
If you need to run a clean up script for your SAST environment, please refer to the Mend SAST clean up kit in the [Mend Toolkit](https://github.com/mend-toolkit/mend-examples/tree/main/Scripts/Mend%20SAST) 

**note:** The optimal cleanup scope is derived from the size of the environment, Mend scope size (memory and CPU) allocated for the server, and runtime time constraints.    


