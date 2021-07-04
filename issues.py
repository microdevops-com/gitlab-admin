#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Discovering properties:
# https://jira.readthedocs.io/en/latest/jirashell.html

# Import common code
from sysadmws_common import *

import gitlab
import glob
import textwrap
import subprocess
import json
import re
import datetime
import jira
import requests

# Constants and envs

LOGO="Projects"
WORK_DIR = "./"
LOG_DIR = "./log"
LOG_FILE = "issues.log"
PROJECTS_YAML = "issues.yaml"

# Defs
def jira_to_md(text):

    # Find all @xxxxxx:xxxx-xxx - accounts in jira
    for match in re.finditer(" @[a-zA-Z0-9-:]+", text):

        # Remove first whitespace and @ in match
        account_id = match[0][2:]

        # Get account info
        request = requests.get("{url}/rest/api/3/user?accountId={accountId}".format(url=issues_yaml_dict["import_issues_from_jira"]["jira"]["url"], accountId=account_id), auth=(issues_yaml_dict["import_issues_from_jira"]["jira"]["user"], JIRA_PRIVATE_TOKEN))
        account_info = json.loads(request.text)
        if "displayName" in account_info:
            account_text = "@" + account_info["displayName"]
            if "emailAddress" in account_info:
                account_text += " (" + account_info["emailAddress"] + ")"
            # Replace account links
            text = text.replace("@" + account_id, account_text)

    # Find all [~accountid:xxxx:xxxx-xxx] - accounts in jira
    for match in re.finditer("\[~accountid:[a-zA-Z0-9-:]+\]", text):

        # Remove first whitespace and @ in match
        account_id = match[0][12:-1]

        # Get account info
        request = requests.get("{url}/rest/api/3/user?accountId={accountId}".format(url=issues_yaml_dict["import_issues_from_jira"]["jira"]["url"], accountId=account_id), auth=(issues_yaml_dict["import_issues_from_jira"]["jira"]["user"], JIRA_PRIVATE_TOKEN))
        account_info = json.loads(request.text)
        if "displayName" in account_info:
            account_text = "@" + account_info["displayName"]
            if "emailAddress" in account_info:
                account_text += " (" + account_info["emailAddress"] + ")"
            # Replace account links
            text = text.replace("[~accountid:" + account_id + "]", account_text)

    # Replace noformat to code lock
    text = text.replace("{noformat}", "```")
    return text

# Main

if __name__ == "__main__":

    # Set parser and parse args
    parser = argparse.ArgumentParser(description='{LOGO} functions.'.format(LOGO=LOGO))
    parser.add_argument("--debug", dest="debug", help="enable debug", action="store_true")
    parser.add_argument("--dry-run-gitlab", dest="dry_run_gitlab", help="no new objects created in gitlab", action="store_true")
    parser.add_argument("--yaml", dest="yaml", help="use file FILE instead of default issues.yaml", nargs=1, metavar=("FILE"))
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--import-issues-from-jira", dest="import_issues_from_jira", help="import issues from jira with rules defined in yaml", action="store_true")
    group.add_argument("--import-epics-from-jira", dest="import_epics_from_jira", help="import issues as epics from jira with rules defined in yaml", action="store_true")
    group.add_argument("--import-milestones-from-jira", dest="import_milestones_from_jira", help="import issues as milestones from jira with rules defined in yaml", action="store_true")
    args = parser.parse_args()

    # Set logger and console debug
    if args.debug:
        logger = set_logger(logging.DEBUG, LOG_DIR, LOG_FILE)
    else:
        logger = set_logger(logging.ERROR, LOG_DIR, LOG_FILE)

    GL_ADMIN_PRIVATE_TOKEN = os.environ.get("GL_ADMIN_PRIVATE_TOKEN")
    if GL_ADMIN_PRIVATE_TOKEN is None:
        raise Exception("Env var GL_ADMIN_PRIVATE_TOKEN missing")

    JIRA_PRIVATE_TOKEN = os.environ.get("JIRA_PRIVATE_TOKEN")
    if JIRA_PRIVATE_TOKEN is None:
        raise Exception("Env var JIRA_PRIVATE_TOKEN missing")

    # Catch exception to logger

    try:

        logger.info("Starting {LOGO}".format(LOGO=LOGO))

        # Chdir to work dir
        os.chdir(WORK_DIR)

        # Read isssues
        if args.yaml is not None:
            issues_yaml_dict = load_yaml("{0}".format(args.yaml[0]), logger)
            if issues_yaml_dict is None:
                raise Exception("Config file error or missing: {0}".format(args.yaml[0]))
        else:
            issues_yaml_dict = load_yaml("{0}/{1}".format(WORK_DIR, PROJECTS_YAML), logger)
            if issues_yaml_dict is None:
                raise Exception("Config file error or missing: {0}/{1}".format(WORK_DIR, PROJECTS_YAML))
        
        # Do tasks

        if args.import_epics_from_jira:
            
            # Connect to GitLab
            gl = gitlab.Gitlab(issues_yaml_dict["gitlab"]["url"], private_token=GL_ADMIN_PRIVATE_TOKEN)
            gl.auth()

            # Connect to Jira
            jira = jira.JIRA(issues_yaml_dict["import_epics_from_jira"]["jira"]["url"], basic_auth=(issues_yaml_dict["import_epics_from_jira"]["jira"]["user"], JIRA_PRIVATE_TOKEN))

            # Jira custom fields map
            jira_fields = jira.fields()
            jira_fields_name_map = {jira.field["name"]:jira.field["id"] for jira.field in jira_fields}

            # Get gitlab group
            gitlab_group = gl.groups.get(issues_yaml_dict["import_epics_from_jira"]["gitlab_group_path"])
            logger.info("Found group ID: {id}, name: {group}".format(group=gitlab_group.full_name, id=gitlab_group.id))

            # Search jira issues
            jira_issues = jira.search_issues(issues_yaml_dict["import_epics_from_jira"]["search_issues"], maxResults=None)

            # Iterate issues in jira
            for jira_issue in jira_issues:

                logger.info("Importing Jira issue: {jira_issue_key}".format(jira_issue_key=jira_issue.key))

                # Prepare data for gitlab epic
                gitlab_epic_data = {}

                # Title
                gitlab_epic_data["title"] = jira_issue.fields.summary

                # Created at
                gitlab_epic_data["created_at"] = jira_issue.fields.created

                # Jira original issue
                gitlab_epic_data["description"] = "Jira Link: {jira_url}/browse/{key}\n\n".format(jira_url=issues_yaml_dict["import_epics_from_jira"]["jira"]["url"], key=jira_issue.key)

                # Jira Reporter
                gitlab_epic_data["description"] += "Jira Reporter: {reporter}\n\n".format(reporter=jira_issue.fields.reporter.displayName)

                # Jira attachment links
                expanded_att_jira_issue = jira.issue(jira_issue.key, expand="attachment")
                if len(expanded_att_jira_issue.fields.attachment):
                    gitlab_epic_data["description"] += "Jira Attachments:\n"
                    for att in expanded_att_jira_issue.fields.attachment:
                        gitlab_epic_data["description"] += "- {content}\n".format(content=att.content)
                    gitlab_epic_data["description"] += "\n"

                # Priority Labels
                gitlab_epic_data["labels"] = "Priority::" + jira_issue.fields.priority.name

                # Due Date
                gitlab_epic_data["due_date_fixed"] = jira_issue.fields.duedate

                # Labels
                for label in jira_issue.fields.labels:
                    if "label_map" in issues_yaml_dict["import_epics_from_jira"]:
                        if label in issues_yaml_dict["import_epics_from_jira"]["label_map"]:
                            gitlab_epic_data["labels"] += "," + issues_yaml_dict["import_epics_from_jira"]["label_map"][label]
                        else:
                            gitlab_epic_data["labels"] += "," + label

                # Description
                if jira_issue.fields.description is not None:
                    gitlab_epic_data["description"] += jira_to_md(jira_issue.fields.description)
                    gitlab_epic_data["description"] += "\n"

                # Checklist
                if getattr(jira_issue.fields, jira_fields_name_map["Checklist Text"]) is not None:
                    for checklist_item in getattr(jira_issue.fields, jira_fields_name_map["Checklist Text"]).splitlines():

                        # Check first 5 symbols in item - check mark
                        if checklist_item[0:5] == "* [x]":
                            gitlab_epic_data["description"] += "- [x] "
                            gitlab_epic_data["description"] += jira_to_md(checklist_item[6:])
                        else:
                            gitlab_epic_data["description"] += "- [ ] "
                            gitlab_epic_data["description"] += jira_to_md(checklist_item[2:])
                        gitlab_epic_data["description"] += "\n"
                
                # Status to Label
                if "status_to_label_map" in issues_yaml_dict["import_epics_from_jira"] and jira_issue.fields.status.name in issues_yaml_dict["import_epics_from_jira"]["status_to_label_map"]:
                    gitlab_epic_data["labels"] += "," + issues_yaml_dict["import_epics_from_jira"]["status_to_label_map"][jira_issue.fields.status.name]
                else:
                    if jira_issue.fields.status.name != "Done":
                        logger.info("Status {status} not found in status_to_label_map".format(status=jira_issue.fields.status.name))
                    
                # Create Epic in GitLab
                gitlab_epic = gitlab_group.epics.create(gitlab_epic_data)
                logger.info("GitLab Epic created: {web_url}".format(web_url=gitlab_epic.web_url))

                # Comments
                expanded_comments_jira_issue = jira.issue(jira_issue.key, expand="changelog", fields="comment")
                for comment in expanded_comments_jira_issue.raw["fields"]["comment"]["comments"]:
                    comment_body = comment["author"]["displayName"]
                    if "emailAddress" in comment["author"]:
                        comment_body += " (" + comment["author"]["emailAddress"] + ")"
                        comment_body += ":\n\n"
                    comment_body += jira_to_md(comment["body"])
                    gitlab_epic.notes.create({"body": comment_body, "created_at": comment["created"]})

                # State
                if jira_issue.fields.status.name == "Done":
                    gitlab_epic.state_event = "close"

                # Updated at
                gitlab_epic.updated_at = jira_issue.fields.updated

                # Save
                # Dump attr change otherwise save may produce errors
                gitlab_epic.title = jira_issue.fields.summary
                gitlab_epic.save()

        if args.import_milestones_from_jira:
            
            # Connect to GitLab
            gl = gitlab.Gitlab(issues_yaml_dict["gitlab"]["url"], private_token=GL_ADMIN_PRIVATE_TOKEN)
            gl.auth()

            # Connect to Jira
            jira = jira.JIRA(issues_yaml_dict["import_milestones_from_jira"]["jira"]["url"], basic_auth=(issues_yaml_dict["import_milestones_from_jira"]["jira"]["user"], JIRA_PRIVATE_TOKEN))

            # Jira custom fields map
            jira_fields = jira.fields()
            jira_fields_name_map = {jira.field["name"]:jira.field["id"] for jira.field in jira_fields}

            # Get gitlab project
            gitlab_project = gl.projects.get(issues_yaml_dict["import_issues_from_jira"]["gitlab_project_path"])

            # Search jira issues
            jira_issues = jira.search_issues(issues_yaml_dict["import_milestones_from_jira"]["search_issues"], maxResults=None)

            # Iterate issues in jira
            for jira_issue in jira_issues:

                logger.info("Importing Jira issue: {jira_issue_key}".format(jira_issue_key=jira_issue.key))

                # Prepare data for gitlab milestone
                gitlab_milestone_data = {}

                # Title
                gitlab_milestone_data["title"] = jira_issue.fields.summary

                # Created at
                gitlab_milestone_data["created_at"] = jira_issue.fields.created

                # Jira original issue
                gitlab_milestone_data["description"] = "Jira Link: {jira_url}/browse/{key}\n\n".format(jira_url=issues_yaml_dict["import_milestones_from_jira"]["jira"]["url"], key=jira_issue.key)

                # Jira Reporter
                gitlab_milestone_data["description"] += "Jira Reporter: {reporter}\n\n".format(reporter=jira_issue.fields.reporter.displayName)

                # Jira attachment links
                expanded_att_jira_issue = jira.issue(jira_issue.key, expand="attachment")
                if len(expanded_att_jira_issue.fields.attachment):
                    gitlab_milestone_data["description"] += "Jira Attachments:\n"
                    for att in expanded_att_jira_issue.fields.attachment:
                        gitlab_milestone_data["description"] += "- {content}\n".format(content=att.content)
                    gitlab_milestone_data["description"] += "\n"

                # Due Date
                gitlab_milestone_data["due_date"] = jira_issue.fields.duedate

                # Description
                if jira_issue.fields.description is not None:
                    gitlab_milestone_data["description"] += jira_to_md(jira_issue.fields.description)
                    gitlab_milestone_data["description"] += "\n"

                # Checklist
                if getattr(jira_issue.fields, jira_fields_name_map["Checklist Text"]) is not None:
                    for checklist_item in getattr(jira_issue.fields, jira_fields_name_map["Checklist Text"]).splitlines():

                        # Check first 5 symbols in item - check mark
                        if checklist_item[0:5] == "* [x]":
                            gitlab_milestone_data["description"] += "- [x] "
                            gitlab_milestone_data["description"] += jira_to_md(checklist_item[6:])
                        else:
                            gitlab_milestone_data["description"] += "- [ ] "
                            gitlab_milestone_data["description"] += jira_to_md(checklist_item[2:])
                        gitlab_milestone_data["description"] += "\n"
                
                # Create Milestone in GitLab
                gitlab_milestone = gitlab_project.milestones.create(gitlab_milestone_data)
                logger.info("GitLab Milestone created: {web_url}".format(web_url=gitlab_milestone.web_url))

                # State
                if jira_issue.fields.status.name == "Done":
                    gitlab_milestone.state_event = "close"

                # Updated at
                gitlab_milestone.updated_at = jira_issue.fields.updated

                # Save
                # Dump attr change otherwise save may produce errors
                gitlab_milestone.title = jira_issue.fields.summary
                gitlab_milestone.save()

        if args.import_issues_from_jira:
            
            # Connect to GitLab
            gl = gitlab.Gitlab(issues_yaml_dict["gitlab"]["url"], private_token=GL_ADMIN_PRIVATE_TOKEN)
            gl.auth()

            # Connect to Jira
            jira = jira.JIRA(issues_yaml_dict["import_issues_from_jira"]["jira"]["url"], basic_auth=(issues_yaml_dict["import_issues_from_jira"]["jira"]["user"], JIRA_PRIVATE_TOKEN))

            # Jira custom fields map
            jira_fields = jira.fields()
            jira_fields_name_map = {jira.field["name"]:jira.field["id"] for jira.field in jira_fields}

            # Get gitlab project
            gitlab_project = gl.projects.get(issues_yaml_dict["import_issues_from_jira"]["gitlab_project_path"])

            # Search jira issues
            jira_issues = jira.search_issues(issues_yaml_dict["import_issues_from_jira"]["search_issues"], maxResults=None)

            # Iterate issues in jira
            for jira_issue in jira_issues:

                # Skip bad issues by list
                if "skip_issues" in issues_yaml_dict["import_issues_from_jira"] and jira_issue.key in issues_yaml_dict["import_issues_from_jira"]["skip_issues"]:
                    logger.info("Skipping Jira issue: {jira_issue_key}".format(jira_issue_key=jira_issue.key))
                    continue
                else:
                    logger.info("Importing Jira issue: {jira_issue_key}".format(jira_issue_key=jira_issue.key))

                # Prepare data for gitlab issue
                gitlab_issue_data = {}

                # Title
                gitlab_issue_data["title"] = jira_issue.fields.summary

                # Created at
                gitlab_issue_data["created_at"] = jira_issue.fields.created

                # Jira original issue
                gitlab_issue_data["description"] = "Jira Link: {jira_url}/browse/{key}\n\n".format(jira_url=issues_yaml_dict["import_issues_from_jira"]["jira"]["url"], key=jira_issue.key)

                # Jira Reporter
                gitlab_issue_data["description"] += "Jira Reporter: {reporter}\n\n".format(reporter=jira_issue.fields.reporter.displayName)

                # Jira attachment links
                expanded_att_jira_issue = jira.issue(jira_issue.key, expand="attachment")
                if len(expanded_att_jira_issue.fields.attachment):
                    gitlab_issue_data["description"] += "Jira Attachments:\n"
                    for att in expanded_att_jira_issue.fields.attachment:
                        gitlab_issue_data["description"] += "- {content}\n".format(content=att.content)
                    gitlab_issue_data["description"] += "\n"

                # Assignee
                # Apply name_map
                if jira_issue.fields.assignee is not None:
                    if "name_map" in issues_yaml_dict["import_issues_from_jira"]:
                        if jira_issue.fields.assignee.displayName in issues_yaml_dict["import_issues_from_jira"]["name_map"]:
                            display_name_to_search = issues_yaml_dict["import_issues_from_jira"]["name_map"][jira_issue.fields.assignee.displayName]
                        else:
                            display_name_to_search = jira_issue.fields.assignee.displayName
                    else:
                        display_name_to_search = jira_issue.fields.assignee.displayName
                    # Get list by name search
                    gl_assignee_user_list = gl.users.list(search=display_name_to_search)
                    # Search by Name - the only always existing field and make sure exact search
                    if len(gl_assignee_user_list) and gl_assignee_user_list[0].name == display_name_to_search:
                        gitlab_issue_data["assignee_ids"] = [gl_assignee_user_list[0].id]

                # Priority Labels
                gitlab_issue_data["labels"] = "Priority::" + jira_issue.fields.priority.name

                # Due Date
                gitlab_issue_data["due_date"] = jira_issue.fields.duedate

                # Labels
                for label in jira_issue.fields.labels:
                    if "label_map" in issues_yaml_dict["import_issues_from_jira"]:
                        if label in issues_yaml_dict["import_issues_from_jira"]["label_map"]:
                            gitlab_issue_data["labels"] += "," + issues_yaml_dict["import_issues_from_jira"]["label_map"][label]
                        else:
                            gitlab_issue_data["labels"] += "," + label

                # Epic
                if hasattr(jira_issue.fields, "parent"):
                    if jira_issue.fields.parent.key in issues_yaml_dict["import_issues_from_jira"]["parent_to_epic_map"]:
                        gitlab_group = gl.groups.get(issues_yaml_dict["import_epics_from_jira"]["gitlab_group_path"])
                        logger.info("Found group ID: {id}, name: {group}".format(group=gitlab_group.full_name, id=gitlab_group.id))
                        epic = gitlab_group.epics.get(issues_yaml_dict["import_issues_from_jira"]["parent_to_epic_map"][jira_issue.fields.parent.key])
                        logger.info("Found epic ID: {id}, name: {epic}".format(epic=epic.title, id=epic.id))
                        gitlab_issue_data["epic_id"] = epic.id
                    elif jira_issue.fields.parent.key in issues_yaml_dict["import_issues_from_jira"]["parent_to_milestone_map"]:
                        milestone = None
                        for ms in gitlab_project.milestones.list():
                            if ms.iid == issues_yaml_dict["import_issues_from_jira"]["parent_to_milestone_map"][jira_issue.fields.parent.key]:
                                ms_id = ms.id
                        milestone = gitlab_project.milestones.get(ms_id)
                        logger.info("Found milestone ID: {id}, name: {milestone}".format(milestone=milestone.title, id=milestone.id))
                        gitlab_issue_data["milestone_id"] = milestone.id
                    else:
                        raise Exception("Issue parent is not defined neither in parent_to_epic_map nor in parent_to_milestone_map")

                # Description
                if jira_issue.fields.description is not None:
                    gitlab_issue_data["description"] += jira_to_md(jira_issue.fields.description)
                    gitlab_issue_data["description"] += "\n"

                # Checklist
                if getattr(jira_issue.fields, jira_fields_name_map["Checklist Text"]) is not None:
                    for checklist_item in getattr(jira_issue.fields, jira_fields_name_map["Checklist Text"]).splitlines():

                        # Check first 5 symbols in item - check mark
                        if checklist_item[0:5] == "* [x]":
                            gitlab_issue_data["description"] += "- [x] "
                            gitlab_issue_data["description"] += jira_to_md(checklist_item[6:])
                        else:
                            gitlab_issue_data["description"] += "- [ ] "
                            gitlab_issue_data["description"] += jira_to_md(checklist_item[2:])
                        gitlab_issue_data["description"] += "\n"
                
                # Status to Label
                if "status_to_label_map" in issues_yaml_dict["import_issues_from_jira"] and jira_issue.fields.status.name in issues_yaml_dict["import_issues_from_jira"]["status_to_label_map"]:
                    gitlab_issue_data["labels"] += "," + issues_yaml_dict["import_issues_from_jira"]["status_to_label_map"][jira_issue.fields.status.name]
                else:
                    if jira_issue.fields.status.name != "Done":
                        logger.info("Status {status} not found in status_to_label_map".format(status=jira_issue.fields.status.name))
                    
                # Create Issue in GitLab
                gitlab_issue = gitlab_project.issues.create(gitlab_issue_data)
                logger.info("GitLab Issue created: {web_url}".format(web_url=gitlab_issue.web_url))

                # Comments
                expanded_comments_jira_issue = jira.issue(jira_issue.key, expand="changelog", fields="comment")
                for comment in expanded_comments_jira_issue.raw["fields"]["comment"]["comments"]:
                    comment_body = comment["author"]["displayName"]
                    if "emailAddress" in comment["author"]:
                        comment_body += " (" + comment["author"]["emailAddress"] + ")"
                        comment_body += ":\n\n"
                    comment_body += jira_to_md(comment["body"])
                    gitlab_issue.notes.create({"body": comment_body, "created_at": comment["created"]})

                # State
                if jira_issue.fields.status.name == "Done":
                    gitlab_issue.state_event = "close"

                # Updated at
                gitlab_issue.updated_at = jira_issue.fields.updated

                # Save
                # Dump attr change otherwise save may produce errors
                gitlab_issue.title = jira_issue.fields.summary
                gitlab_issue.save()

    # Reroute catched exception to log
    except Exception as e:
        logger.exception(e)
        logger.error("Finished {LOGO} with errors in file {file}".format(LOGO=LOGO, file=args.yaml[0] if args.yaml is not None else WORK_DIR + "/" + PROJECTS_YAML))
        sys.exit(1)

    logger.info("Finished {LOGO}".format(LOGO=LOGO))
