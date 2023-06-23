import http.client
import json
import sys
import argparse
import re
import os
import uuid
from datetime import timedelta, datetime
from distutils.util import strtobool
from configparser import ConfigParser
from mend_sca_cleanup_tool._version import __description__, __tool_name__, __version__


ATTRIBUTION = "attribution"
FILTER_PROJECTS_BY_UPDATE_TIME = "FilterProjectsByUpdateTime"
FILTER_PROJECTS_BY_LAST_CREATED_COPIES = "FilterProjectsByLastCreatedCopies"
HEADERS = {
    'Content-Type': 'application/json',
    'agent': f"ps-{__tool_name__}".replace('_', '-'),
    'agentVersion': __version__,
    'ctxId': uuid.uuid1().__str__()
}
IGNORED_ALERTS = "ignored_alerts"
RESOLVED_ALERTS = "resolved_alerts"
REJECTED_BY_POLICY = "alerts_rejected_by_policy"
REPORTS = {
           "bugs": "getProjectBugsReport",
           IGNORED_ALERTS: "getProjectSecurityAlertsByVulnerabilityReport",
           REJECTED_BY_POLICY: "getProjectAlertsByType",
           "in_house_libraries": "getProjectInHouseReport",
           "license_compatibility": "getProjectLicenseCompatibilityReport",
           RESOLVED_ALERTS: "getProjectSecurityAlertsByVulnerabilityReport",
           "source_files": "getProjectSourceFileInventoryReport", 
           "alerts": "getProjectSecurityAlertsByVulnerabilityReport",
           ATTRIBUTION: "getProjectAttributionReport",
           "due_diligence": "getProjectDueDiligenceReport",
           "inventory": "getProjectInventoryReport",
           "request_history": "getProjectRequestHistoryReport",
           "source_file_inventory": "getProjectSourceFileInventoryReport",
           "vulnerability": "getProjectVulnerabilityReport"
           }

def main():
    global CONFIG
    global MAIN_API_CONNECTION
    if len(sys.argv) == 1:
        CONFIG = parse_config_file("params.config")
    elif not sys.argv[1].startswith('-'):
        CONFIG = parse_config_file(sys.argv[1])
    else:
        CONFIG = parse_args()
    
    setup_config()

    MAIN_API_CONNECTION = http.client.HTTPSConnection(CONFIG.mend_url)

    if CONFIG.dry_run:
        print("Dry Run enabled - no reports or deletions will occur")

    product_project_dict = get_projects_to_remove()


    total_projects_to_delete = (sum([len(product_project_dict[x]) for x in product_project_dict]))
    if not CONFIG.dry_run:
        if total_projects_to_delete == 0:
            print("No projects to clean up were found")
            exit()
        else:
            print(f"Found {total_projects_to_delete} project(s) to delete, generating reports and removing project(s)...")
        for product_token in product_project_dict:
            for project in product_project_dict[product_token]:
                if not CONFIG.skip_report_generation:
                    try:
                        generate_reports(project)
                    except:
                        print(f"There was an issue with the report generation, skipping deletion for project: {project['name']}")
                        continue
                else:
                    print("skipReportGeneration flag found, skipping report generation")
                if not CONFIG.skip_project_deletion:
                    delete_scan(product_token, project)
                else:
                    print("skipProjectDeletion flag found, skipping project deletion")
    else:
        print(f"Dry Run found {total_projects_to_delete} project(s) to delete: {[project['name'] for projects in product_project_dict.values() for project in projects]}")

def check_response_error(obj_response):
    if isinstance(obj_response, dict):
        if "errorMessage" in obj_response:
            print(f"There was an issue with the request: {obj_response['errorMessage']}")
            return True
        else:
            return False

def create_output_directory(product_name, project_name):
    product_name = remove_invalid_chars(product_name)
    project_name = remove_invalid_chars(project_name)
    if not CONFIG.output_dir.endswith("\\"):
        CONFIG.output_dir = CONFIG.output_dir + "\\"
    output_dir = CONFIG.output_dir + product_name + "\\" + project_name + "\\"
    if len(output_dir) > 180:
        output_dir = (output_dir[:180] + "..")
    if not os.path.exists(output_dir):
        print(f"Making directory {output_dir}")
        os.makedirs(output_dir)
    return output_dir

def delete_scan(product_token, project):
    print(f"Deleting project: {project['name']}")
    request = json.dumps({
                "requestType": "deleteProject",
                "userKey": CONFIG.mend_user_key,
                "productToken": product_token,
                "projectToken": project['token']
            })
    response_obj = json.loads(post_api_request(request).decode("utf-8"))
    if check_response_error(response_obj):
        return

def filter_projects_by_config(projects):
    projects_to_return = [project for project in projects if project['token'] not in CONFIG.excluded_project_tokens]
    if len(projects_to_return) == 0:
        return []

    if CONFIG.excluded_project_name_patterns:
        print(f"Filtering projects with name containing values {CONFIG.project_name_exclude_list}")
        for patt in CONFIG.project_name_exclude_list:
            projects_to_return = [project for project in projects_to_return for k, v in project.items() if k == "name" and patt not in v]

    if CONFIG.operation_mode == FILTER_PROJECTS_BY_UPDATE_TIME:
        archive_date = (datetime.utcnow() - timedelta(days=CONFIG.days_to_keep))
        print(f"Filtering projects older than: {archive_date}")
        projects_to_return = [project for project in projects_to_return if archive_date.timestamp() > datetime.strptime(project['lastUpdatedDate'],'%Y-%m-%d %H:%M:%S %z').timestamp()]

    if CONFIG.analyzed_project_tag:
        print(f"Filtering projects based on project tag: {CONFIG.analyzed_project_tag}")
        projects_to_return = filter_projects_by_tag_with_exact_match(projects_to_return) 

    if CONFIG.analyzed_project_tag_regex_in_value:
        print(f"Filtering projects based on project contain tag value: {CONFIG.analyzed_project_tag_regex_in_value}")
        projects_to_return = filter_projects_by_tag_with_contains_match(projects_to_return)

    if CONFIG.operation_mode == FILTER_PROJECTS_BY_LAST_CREATED_COPIES:
        print(f"Filtering projects besides most recent: {CONFIG.days_to_keep}")
        if len(projects_to_return) > CONFIG.days_to_keep:
            index = len(projects_to_return) - CONFIG.days_to_keep
            print(f"Total: {len(projects_to_return)}. Removing oldest {index}")
            projects_to_return = sorted(projects_to_return, key=lambda d: d['lastUpdatedDate'])
            projects_to_return = projects_to_return[:index]
        else:
            print(f"Total: {len(projects_to_return)}. Nothing to filter")
    print(f"{len(projects_to_return)} project(s) to remove after filtering")
    return projects_to_return

def filter_projects_by_tag_with_exact_match(projects):
    projects_to_return = []
    for project in projects:
        project_tags = get_project_tags(project)
        if CONFIG.tag_pair[1] in project_tags.get(CONFIG.tag_pair[0], ''):
            print(f"{project['name']} has matching tag")
            projects_to_return.append(project)
    return projects_to_return

def filter_projects_by_tag_with_contains_match(projects):
    projects_to_return = []
    for project in projects:
        project_tags = get_project_tags(project)
        for k, v in project_tags.items():
            if CONFIG.tag_pair[0] in k and any(CONFIG.tag_pair[1] in item for item in v):
                print(f"{project['name']} contains tag value")
                projects_to_return.append(project)
    return projects_to_return

def generate_reports(project):
    print(f"Generating reports for project: {project['name']}")
    project_token = project['token']
    reports_to_generate = get_reports_to_generate()
    if len(reports_to_generate) > 0:
        output_dir = create_output_directory(project['productName'], project['name'])
        for report in reports_to_generate.keys():
            print(f"Generating {report} report for project {project['name']}")
            reportFormat = 'xlsx'
            if report.lower() == ATTRIBUTION:
                data = get_attribution_report(project_token)
                reportFormat = 'html'
            elif report.lower() == RESOLVED_ALERTS:
                data = get_alerts_report(reports_to_generate[report], project_token, "resolved")
            elif report.lower() == IGNORED_ALERTS:
                data = get_alerts_report(reports_to_generate[report], project_token, "ignored")
            elif report.lower() == REJECTED_BY_POLICY:
                data = get_alerts_by_type(reports_to_generate[report], project_token, "REJECTED_BY_POLICY_RESOURCE")
                reportFormat = "json"
            else:
                data = get_excel_report(reports_to_generate[report], project_token)

            generation_failed = check_response_error(data)
            if generation_failed:
                raise Exception(f"Failed to generate report: {report}") 
            report = open(output_dir + report + '.' + reportFormat, "wb")
            report.write(data)
            report.close()
    else:
        print("No reports to generate")


def get_alerts_report(request_type, project_token, alertType):
    request = json.dumps({
        "requestType": request_type,
        "userKey": CONFIG.mend_user_key,
        "projectToken": project_token,
        "status": alertType,
        "format": "xlsx"
    })
    return post_api_request(request)

def get_alerts_by_type(request_type, project_token, alertType):
    request = json.dumps({
        "requestType": request_type,
        "userKey": CONFIG.mend_user_key,
        "projectToken": project_token,
        "alertType": alertType
    })
    return post_api_request(request)

def get_attribution_report(project_token):
    request = json.dumps({
        "requestType": REPORTS[ATTRIBUTION],
        "userKey": CONFIG.mend_user_key,
        "projectToken": project_token,
        "reportingAggregationMode": "BY_PROJECT",
        "exportFormat": "html"
    })
    return post_api_request(request)

def get_config_file_value(config_val, default):
        if isinstance(config_val, int):
            return config_val if config_val is not None else default
        return config_val if config_val else default

def get_excel_report(request_type, project_token):
    request = json.dumps({
        "requestType": request_type,
        "userKey": CONFIG.mend_user_key,
        "projectToken": project_token,
        "format": "xlsx"
    })
    return post_api_request(request)

def get_reports_to_generate():
    if len(CONFIG.report_types) == 0:
        return REPORTS
    else:
        reportKeys = CONFIG.report_types.replace(" ", "").split(',')
        report_dictionary = dict((k, REPORTS[k]) for k in reportKeys if k in REPORTS)
        if len(report_dictionary) != len(reportKeys):
            unmatched_keys = [k for k in reportKeys if k not in report_dictionary.keys()]
            for unmatched_key in unmatched_keys:
                print(f"Could not generate report for {unmatched_key}. Unsupported report, please reference the README for supported reports")
        return report_dictionary


def get_products():
    request = json.dumps({
        "requestType": "getAllProducts",
        "userKey": CONFIG.mend_user_key,
        "orgToken": CONFIG.mend_api_token,
    })
    response_obj = json.loads(post_api_request(request).decode("utf-8"))
    if check_response_error(response_obj):
        exit()
    if len(CONFIG.included_product_tokens) == 0:
        return [product for product in response_obj['products'] if product['productToken'] not in CONFIG.excluded_product_tokens]
    else:
        return [product for product in response_obj['products'] if product['productToken'] in CONFIG.included_product_tokens and product['productToken'] not in CONFIG.excluded_product_tokens]

def get_projects(product_token):
    request = json.dumps({
        "requestType": "getProductProjectVitals",
        "userKey": CONFIG.mend_user_key,
        "productToken": product_token,
    })
    response_obj = json.loads(post_api_request(request).decode("utf-8"))
    if check_response_error(response_obj):
        exit()
    else:
        return [vital_Response for vital_Response in response_obj['projectVitals']]

def get_project_tags(project):
    print(f"Getting tags for project {project['name']}")
    request = json.dumps({
            "requestType": "getProjectTags",
            "userKey": CONFIG.mend_user_key,
            "projectToken": project['token'],
        })
    response_obj = json.loads(post_api_request(request).decode("utf-8"))
    if check_response_error(response_obj):
        exit()
    return [project_tags['tags'] for project_tags in response_obj['projectTags']][0]

def get_projects_to_remove():
    projects_to_remove = {}
    products = get_products()
    for product in products:
        print(f"Getting projects to remove for product: {product['productName']}")
        projects = get_projects(product['productToken'])
        projects_length = len(projects)
        if projects_length:
            print(f"Product has {projects_length} project(s)")
            filtered_projects = filter_projects_by_config(projects)
            filted_projects_total = len(filtered_projects)
            if filted_projects_total > 0:
                projects_to_remove[product['productToken']] = filtered_projects
        else:
            print(f"No projects found for product: {product['productName']}")
    return projects_to_remove

def parse_args():
    parser = argparse.ArgumentParser(description="Mend SCA Clean up tool")
    parser.add_argument('-a', '--mendURL', '--wsURL', help="Mend URL", dest='mend_url', default="saas.whitesourcesoftware.com")
    parser.add_argument('-e', '--excludedProductTokens', help="Excluded Product Tokens (comma seperated list)", dest='excluded_product_tokens')
    parser.add_argument('-g', '--analyzedProjectTag', help="Analyze only the projects whose contain the specific Mend tag (key:value). Case sensitive.", dest='analyzed_project_tag')
    parser.add_argument('-i', '--includedProductTokens', help="Included Product Tokens (comma seperated list)", dest='included_product_tokens')
    parser.add_argument('-j', '--skipProjectDeletion', help="Skip Project Deletion", dest='skip_project_deletion', type=strtobool, default=False)
    parser.add_argument('-k', '--apiToken', '--orgToken', help="Mend API token", dest='mend_api_token', required=True)
    parser.add_argument('-m', '--operationMode', help="Clean up operation method", dest='operation_mode', default=FILTER_PROJECTS_BY_UPDATE_TIME,
                                choices=[s for s in [FILTER_PROJECTS_BY_UPDATE_TIME, FILTER_PROJECTS_BY_LAST_CREATED_COPIES]])
    parser.add_argument('-n', '--excludedProjectNamePatterns', help="List of excluded project name patterns (comma seperated list). Case sensitive.", dest='excluded_project_name_patterns')
    parser.add_argument('-o', '--outputDir', help="Output directory", dest='output_dir', default=os.getcwd() + "\\Mend\\Reports\\")
    parser.add_argument('-p', '--projectParallelismLevel', help="Project parallelism level directory Note: This is currently not used in this version of the mend-sca-cleanup-tool", dest='project_parallelism_level')
    parser.add_argument('-r', '--daysToKeep', help="Number of days to keep (overridden by --dateToKeep)", dest='days_to_keep', type=int, default=50000)
    parser.add_argument('-s', '--skipReportGeneration', help="Skip Report Generation", dest='skip_report_generation', type=strtobool, default=False)
    parser.add_argument('-t', '--reportTypes', help="Report Types to generate (comma seperated list)", dest='report_types')
    parser.add_argument('-u', '--userKey', help="Mend UserKey", dest='mend_user_key', required=True)
    parser.add_argument('-v', '--analyzedProjectTagRegexInValue', help="Analyze only the projects whose match their tag key and the tag value contains the specified regex (key:value). Case sensitive. Note: This was originally broken in the original ws-cleanup-tool. The functionality was adjusted to work as originally written. The naming convention is a misnomer but was kept to avoid breaking existing integrations.", dest='analyzed_project_tag_regex_in_value')
    parser.add_argument('-x', '--excludedProjectTokens', help="Excluded Project Tokens (comma seperated list)", dest='excluded_project_tokens')
    parser.add_argument('-y', '--dryRun', help="Whether to run the tool without performing anything", dest='dry_run', type=strtobool, default=False)
    return parser.parse_args()

def parse_config_file(filepath):
    if os.path.exists(filepath):
        config = ConfigParser()
        config.optionxform = str
        config.read(filepath)
        return argparse.Namespace(
                    mend_user_key=get_config_file_value(config['DEFAULT'].get("MendUserKey", config['DEFAULT'].get("WsUserKey")), os.environ.get("WS_USER_KEY")),
                    mend_api_token=get_config_file_value(config['DEFAULT'].get("MendApiToken", config['DEFAULT'].get("WsOrgToken")), os.environ.get("WS_ORG_TOKEN")),
                    mend_url=get_config_file_value(config['DEFAULT'].get("MendUrl", config['DEFAULT'].get("WsUrl")), os.environ.get("WS_URL")),
                    report_types=get_config_file_value(config['DEFAULT'].get('ReportTypes'), os.environ.get("REPORT_TYPES")),
                    operation_mode=get_config_file_value(config['DEFAULT'].get("OperationMode"), FILTER_PROJECTS_BY_UPDATE_TIME),
                    output_dir=get_config_file_value(config['DEFAULT'].get('OutputDir'), os.getcwd() + "\\Mend\\Reports\\"),
                    excluded_product_tokens=get_config_file_value(config['DEFAULT'].get("ExcludedProductTokens", []), os.environ.get("EXCLUDED_PRODUCT_TOKENS")),
                    included_product_tokens=get_config_file_value(config['DEFAULT'].get("IncludedProductTokens", []), os.environ.get("INCLUDED_PRODUCT_TOKENS")),
                    excluded_project_tokens=get_config_file_value(config['DEFAULT'].get("ExcludedProjectTokens", []), os.environ.get("EXCLUDED_PROJECT_TOKENS")),
                    excluded_project_name_patterns=get_config_file_value(config['DEFAULT'].get("ExcludedProjectNamePatterns", None), os.environ.get("EXCLUDED_PROJECT_NAME_PATTERNS")),
                    analyzed_project_tag=get_config_file_value(config['DEFAULT'].get("AnalyzedProjectTag", None), os.environ.get("ANALYZED_PROJECT_TAG")),
                    analyzed_project_tag_regex_in_value=get_config_file_value(config['DEFAULT'].get("AnalyzedProjectTagRegexInValue", None), os.environ.get("ANALYZED_PROJECT_TAG_REGEX_IN_VALUE")),
                    days_to_keep=get_config_file_value(config['DEFAULT'].getint("DaysToKeep", 50000), os.environ.get("DAYS_TO_KEEP")),
                    project_parallelism_level=config['DEFAULT'].get('ProjectParallelismLevel', 5),
                    dry_run=config['DEFAULT'].getboolean("DryRun", False),
                    skip_report_generation=config['DEFAULT'].getboolean("SkipReportGeneration", False),
                    skip_project_deletion=config['DEFAULT'].getboolean("SkipProjectDeletion", False)
                )
    else:
        print(f"No configuration file found at: {filepath}")
        exit()

def post_api_request(request):
    try:
        MAIN_API_CONNECTION.request("POST", '/api/v1.4', request, HEADERS)
        return MAIN_API_CONNECTION.getresponse().read()
    except:
        sys.exit(f"There was an issue calling the Mend API with URL: {CONFIG.mend_url}")

def remove_invalid_chars(string_to_clean):
    return re.sub('[:*<>/"?|.]', '-', string_to_clean).replace("\\", "-")

def setup_config():
    if not CONFIG.mend_user_key:
        sys.exit(f"A Mend user key was not provided")
    if not CONFIG.mend_api_token:
        sys.exit(f"A Mend Api key was not provided")

    if CONFIG.mend_url:
        CONFIG.mend_url = re.sub("(https?)://", "", CONFIG.mend_url.lower())
        if '/' in CONFIG.mend_url:
            apiIndex = CONFIG.mend_url.find('/')
        else:
            apiIndex = len(CONFIG.mend_url)
        CONFIG.mend_url = CONFIG.mend_url[:apiIndex]
    else:
        sys.exit(f"A Mend URL was not provided") 

    if CONFIG.analyzed_project_tag:
        tag_pair = tuple(CONFIG.analyzed_project_tag.replace(" ", "").split(":"))
        if len(tag_pair) != 2:
            print(f"Unable to parse project tag: {CONFIG.analyzed_project_tag}")
            sys.exit("Expected format of project tags: <name:value>")
        else:
            CONFIG.tag_pair = tag_pair

    if CONFIG.analyzed_project_tag_regex_in_value:
        tag_pair = tuple(CONFIG.analyzed_project_tag_regex_in_value.replace(" ", "").split(":"))
        if len(tag_pair) != 2:
            print(f"Unable to parse project tag: {CONFIG.analyzed_project_tag_regex_in_value}")
            sys.exit("Expected format of project tags: <name:value>")
        else:
            CONFIG.tag_pair = tag_pair

    if CONFIG.days_to_keep is None:
        print("Days to keep was not provided, defaulting to 21")
        CONFIG.days_to_keep = 21
    
    CONFIG.included_product_tokens = CONFIG.included_product_tokens.replace(" ", "").split(",") if CONFIG.included_product_tokens else []
    CONFIG.excluded_product_tokens = CONFIG.excluded_product_tokens.replace(" ", "").split(",") if CONFIG.excluded_product_tokens else []
    CONFIG.excluded_project_tokens = CONFIG.excluded_project_tokens.replace(" ", "").split(",") if CONFIG.excluded_project_tokens else []
    CONFIG.excluded_project_name_patterns = CONFIG.excluded_project_name_patterns.split(",") if CONFIG.excluded_project_name_patterns else []
    CONFIG.report_types = CONFIG.report_types if CONFIG.report_types else []

    if CONFIG.excluded_project_name_patterns:
        CONFIG.project_name_exclude_list = CONFIG.excluded_project_name_patterns
   

if __name__ == "__main__":
    main()