import http.client
import json
import sys
import argparse
import re
import os
from datetime import timedelta, datetime
from distutils.util import strtobool


ATTRIBUTION = "attribution"
FILTER_PROJECTS_BY_UPDATE_TIME = "FilterProjectsByUpdateTime"
FILTER_PROJECTS_BY_LAST_CREATED_COPIES = "FilterProjectsByLastCreatedCopies"
HEADERS = {
  'Content-Type': 'application/json'
}
IGNORED_ALERTS = "ignored_alerts"
RESOLVED_ALERTS = "resolved_alerts"   
REPORTS = {
           "bugs": "getProjectBugsReport",
           IGNORED_ALERTS: "getProjectSecurityAlertsByVulnerabilityReport",
           "alerts_rejected_by_policy": "", # Research
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
    
    CONFIG = parse_args()
    MAIN_API_CONNECTION = http.client.HTTPSConnection(CONFIG.mend_url)
    setup_config()

    projects_to_remove = get_projects_to_remove()
    if not projects_to_remove or len(projects_to_remove) == 0:
        print("No projects to clean up were found")
        exit()

    print("Found {} projects to delete, generating reports and removing projects...".format(len(projects_to_remove)))

    if not CONFIG.dry_run:
        for product_token in projects_to_remove:
            for project in projects_to_remove[product_token]:
                project_token = project['token']
                if not CONFIG.skip_report_generation:
                    print("Genering reports for project: {}".format(project['name']))
                    generate_reports(project, get_reports_to_generate(), create_output_directory(project['productName'], project['name']))
                else:
                    print("skipReportGeneration flag found, skipping report generation")
                if not CONFIG.skip_project_deletion:
                    print("Deleting project: {}".format(project['name']))
                    delete_scan(product_token, project_token)
                else:
                    print("skipProjectDeletion flag found, skipping report generation")

def create_output_directory(product_name, project_name):
    remove_invalid_chars(project_name)
    remove_invalid_chars(project_name)
    output_dir = CONFIG.output_dir + product_name + "\\" + project_name + "\\"
    if len(output_dir) > 180:
        output_dir = (output_dir[:180] + "..")
    if not os.path.exists(output_dir):
        print("Making directory" + output_dir)
        os.makedirs(output_dir)
    return output_dir

def delete_scan(product_token, project_token):
    request = json.dumps({
                "requestType": "deleteProject",
                "userKey": CONFIG.mend_user_key,
                "productToken": product_token,
                "projectToken": project_token
            })
    MAIN_API_CONNECTION.request("POST", '/api/v1.4', request, HEADERS)
    delete_response_obj = json.loads(MAIN_API_CONNECTION.getresponse().read().decode("utf-8"))
    if "errorMessage" in delete_response_obj:
        print("There was an issue with the request: " + delete_response_obj["errorMessage"])
        return
 
def filter_projects_by_config(projects):
    projects_to_return = [project for project in projects if project["token"] not in CONFIG.excluded_project_tokens]
    if len(projects_to_return) == 0:
        return []
    if CONFIG.analyzed_project_tag:
        print("Filtering projects based on project tag:" + CONFIG.analyzed_project_tag )
        projects_to_return = [project for project in [get_project_tag(project) for project in projects_to_return] if CONFIG.tag_pair[1] in project["tags"][0].get(CONFIG.tag_pair[0], '')] 
        print("Found {} projects matching tag".format(len(projects_to_return)))

    #if CONFIG.analyzed_project_tag_regex_in_value:
        #projects_to_return = [get_project_tag(project) for project in projects_to_return]
        #return projects_to_return
    if CONFIG.excluded_project_name_patterns:
        print("Filtering projects with name containing values {}".format(CONFIG.project_name_exclude_list))
        for patt in CONFIG.project_name_exclude_list:
            projects_to_return = [project for project in projects_to_return for k, v in project.items() if k == "name" and patt not in v]
        print("Found {} projects with names matching not containing {}".format(len(projects_to_return),CONFIG.project_name_exclude_list))

    if CONFIG.operation_mode == FILTER_PROJECTS_BY_UPDATE_TIME:
        if CONFIG.date_to_keep is None:
            archive_date = (datetime.utcnow() - timedelta(days=CONFIG.days_to_keep))
        else:
            archive_date = (CONFIG.date_to_keep)
        print("Filtering projects older than: {}".format(archive_date))
        projects_to_return = [project for project in projects_to_return if archive_date.timestamp() > datetime.strptime(project["lastUpdatedDate"],'%Y-%m-%d %H:%M:%S %z').timestamp()]
        print("Found {} projects older than {}".format(len(projects_to_return), archive_date))

    if CONFIG.operation_mode == FILTER_PROJECTS_BY_LAST_CREATED_COPIES:
        print("Filtering projects besides most recent: {}".format(CONFIG.days_to_keep))
        if len(projects_to_return) > CONFIG.days_to_keep:
            index = len(projects_to_return) - CONFIG.days_to_keep
            print("Total: {}. Archiving first {}".format(len(projects_to_return), index))
            projects_to_return = projects_to_return[:index]
        else:
            print("Total: {}. Nothing to filter".format(CONFIG.days_to_keep))
    return projects_to_return


def generate_reports(project, reports_to_generate, output_dir):
    project_token = project['token']
    for report in reports_to_generate.keys():
        format = 'xlsx'
        if report.lower() == ATTRIBUTION:
            data = get_attribution_report(project_token)
            format = 'html'
        elif report.lower() == RESOLVED_ALERTS:
            data = get_alerts_report(reports_to_generate[report], project_token, report, "resolved")
        elif report.lower() == IGNORED_ALERTS:
            data = get_alerts_report(reports_to_generate[report], project_token, report, "ignored")
        else:
            data = get_excel_report(reports_to_generate[report], project_token, report)
        print("Generating {} report for project {}".format(report, project['name']))
        report = open(output_dir + report + '.' + format , "wb")
        report.write(data)
        report.close()


def get_alerts_report(request_type, project_token, filename, alertType):
    request = json.dumps({
        "requestType": request_type,
        "userKey": CONFIG.mend_user_key,
        "projectToken": project_token,
        "status": alertType,
        "format" : "xlsx"

    })
    MAIN_API_CONNECTION.request("POST", "/api/v1.4", request, HEADERS)
    reportRes = MAIN_API_CONNECTION.getresponse()
    return reportRes.read()

def get_attribution_report(project_token):
    request = json.dumps({
        "requestType": REPORTS[ATTRIBUTION],
        "userKey": CONFIG.mend_user_key,
        "projectToken": project_token,
        "reportingAggregationMode": "BY_PROJECT",
        "exportFormat" : "html"
    })
    MAIN_API_CONNECTION.request("POST", "/api/v1.4", request, HEADERS)
    reportRes = MAIN_API_CONNECTION.getresponse()
    return reportRes.read()
        
def get_excel_report(request_type, project_token, filename):
    request = json.dumps({
        "requestType": request_type,
        "userKey": CONFIG.mend_user_key,
        "projectToken": project_token,
        "format" : "xlsx"
    })
    MAIN_API_CONNECTION.request("POST", "/api/v1.4", request, HEADERS)
    reportRes = MAIN_API_CONNECTION.getresponse()
    return reportRes.read()

def get_reports_to_generate():
     if len(CONFIG.report_types) == 0:
         return REPORTS
     else:
         reportKeys = CONFIG.report_types.replace(" ", "").split(',')
         report_dictionary = dict((k, REPORTS[k]) for k in reportKeys if k in REPORTS)
         if len(report_dictionary) != len(reportKeys):
              unmatched_keys = [k for k in reportKeys if k not in report_dictionary.keys()]
              for unmatched_key in unmatched_keys:
                print("Could not generate report for: " + unmatched_key + ". Unsupported report, please reference the README for supported reports")
         return report_dictionary


def get_products():
    if len(CONFIG.included_product_tokens) == 0:
        request = json.dumps({
            "requestType": "getAllProducts",
            "userKey": CONFIG.mend_user_key,
            "orgToken": CONFIG.mend_api_token,
        })
        MAIN_API_CONNECTION.request("POST", '/api/v1.4', request, HEADERS)
        get_response_obj = json.loads(MAIN_API_CONNECTION.getresponse().read().decode("utf-8"))
        return [product for product in get_response_obj['products'] if product["productToken"] not in CONFIG.excluded_product_tokens]
    else:
        return CONFIG.included_product_tokens.replace(" ", "").split(',')

def get_projects(product_token):
    request = json.dumps({
        "requestType": "getProductProjectVitals",
        "userKey": CONFIG.mend_user_key,
        "productToken": product_token,
    })
    MAIN_API_CONNECTION.request("POST", '/api/v1.4', request, HEADERS)
    get_response_obj = json.loads(MAIN_API_CONNECTION.getresponse().read().decode("utf-8"))
    if "errorMessage" in get_response_obj:
        print("There was an issue with the request: " + get_response_obj["errorMessage"])
    else:
        return [vital_Response for vital_Response in get_response_obj['projectVitals']]
    
def get_project_tag(project):
    request = json.dumps({
            "requestType": "getProjectTags",
            "userKey": CONFIG.mend_user_key,
            "projectToken": project["token"],
        })
    MAIN_API_CONNECTION.request("POST", '/api/v1.4', request, HEADERS)
    get_response_obj = json.loads(MAIN_API_CONNECTION.getresponse().read().decode("utf-8"))
    project["tags"] = [project_tags["tags"] for project_tags in get_response_obj["projectTags"]]
    if "errorMessage" in get_response_obj:
        print("There was an issue with the request: " + get_response_obj["errorMessage"])
    return project 
           
def get_projects_to_remove():
    projects_to_remove = {}
    products = get_products()
    for product in products:
            print("Getting projects to remove for product: {}".format(product["productName"]))
            projects = get_projects(product["productToken"])
            if len(projects) > 0:
                filted_projects = filter_projects_by_config(projects)
                if len(filted_projects) > 0:
                    projects_to_remove[product["productToken"]] = filted_projects
            else:
                print("No projects found for product: {}".format(product["productName"]))
    return projects_to_remove

def parse_args():    
    parser = argparse.ArgumentParser(description="Mend SCA Clean up tool")
    parser.add_argument('-a', '--mendURL', help="Mend URL", dest='mend_url', required=True) 
    parser.add_argument('-d', '--dateToKeep', help="Date of latest scan to keep in YYYY-MM-DD format ", dest='date_to_keep', type=valid_date)
    parser.add_argument('-e', '--excludedProductTokens', help="Excluded Product Tokens (comma seperated list)", dest='excluded_product_tokens', default=[]) 
    parser.add_argument('-g', '--analyzedProjectTag', help="Analyze only the projects whose contain the specific Mend tag (key:value)", dest='analyzed_project_tag') 
    parser.add_argument('-i', '--includedProductTokens', help="Included Product Tokens (comma seperated list)", dest='included_product_tokens', default=[]) 
    parser.add_argument('-j', '--skipProjectDeletion', help="Skip Project Deletion", dest='skip_project_deletion', type=strtobool, default=False)
    parser.add_argument('-k', '--apiToken', help="Mend API token", dest='mend_api_token', required=True) 
    parser.add_argument('-m', '--operationMode', help="Clean up operation method", dest='operation_mode', default=FILTER_PROJECTS_BY_UPDATE_TIME,
                                choices=[s for s in [FILTER_PROJECTS_BY_UPDATE_TIME, FILTER_PROJECTS_BY_LAST_CREATED_COPIES]])
    parser.add_argument('-n', '--excludedProjectNamePatterns', help="List of excluded project name patterns (comma seperated list)", dest='excluded_project_name_patterns', default=[])
    parser.add_argument('-o', '--outputDir', help="Output directory", dest='output_dir', default=os.getcwd() + "\\Mend\\Reports\\")
    parser.add_argument('-r', '--daysToKeep', help="Number of days to keep (overridden by --dateToKeep)", dest='days_to_keep', type=int, default=21)
    parser.add_argument('-s', '--skipReportGeneration', help="Skip Report Generation", dest='skip_report_generation', type=strtobool, default=False)
    parser.add_argument('-t', '--reportTypes', help="Report Types to generate (comma seperated list)", dest='report_types', default=[])
    parser.add_argument('-u', '--userKey', help="Mend UserKey", dest='mend_user_key', required=True) 
    parser.add_argument('-v', '--analyzedProjectTagRegexInValue', help="Analyze only the projects whose match their tag key and the tag value contains the specified regex (key:regexValue)", dest='analyzed_project_tag_regex_in_value') 
    parser.add_argument('-x', '--excludedProjectTokens', help="Excluded Project Tokens (comma seperated list)", dest='excluded_project_tokens',  default=[]) 
    parser.add_argument('-y', '--dryRun', help="Whether to run the tool without performing anything", dest='dry_run', type=strtobool, default=False)
    return parser.parse_args()

def remove_invalid_chars(string_to_clean):
    return re.sub('[:*\\<>/"?|]', '-', string_to_clean)

def setup_config():
    if CONFIG.analyzed_project_tag:
        tag_pair = tuple(CONFIG.analyzed_project_tag.replace(" ", "").split(":"))
        if len(tag_pair) != 2:
            print(f"Unable to parse Project tag: {CONFIG.analyzed_project_tag}")
            CONFIG.analyzed_project_tag = None
        else:
            CONFIG.tag_pair = tag_pair
    if CONFIG.excluded_project_name_patterns:
        CONFIG.project_name_exclude_list = CONFIG.excluded_project_name_patterns.replace(" ", "").split(',')
    if CONFIG.analyzed_project_tag_regex_in_value:
        return
  
def valid_date(s):
    try:
        return datetime.strptime(s, "%Y-%m-%d")
    except ValueError:
        msg = "not a valid date: {0!r}".format(s)
        raise argparse.ArgumentTypeError(msg)

if __name__ == "__main__":
    main()