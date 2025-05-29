#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import logging

# Import common code
from common import *

import gitlab
import textwrap
import subprocess
import json
import re
import datetime
import requests
import concurrent.futures
import psycopg2
from rich import print_json
from deepdiff import DeepDiff
# Import GraphQL client
from gql import gql, Client
from gql.transport.requests import RequestsHTTPTransport

# Constants and envs

LOGO = "Projects"
WORK_DIR = "./"
LOG_DIR = "./log"
LOG_FILE = "projects.log"
PROJECTS_YAML = "projects.yaml"
PROJECTS_SUBDIR = ".projects"
CONCURRENT_MAX_WORKERS = 10

# Custom Exceptions
class SubprocessRunError(Exception):
    pass

# Functions

# Function to apply vars for a group or a project (gorp)
def apply_vars_gorp(gorp_kind, yaml_dict, gorp, gorp_dict, variables_clean_all_before_set, logger):

    # Expand defaults gorp_dict to gorp_dict_variables_pre0
    gorp_dict_variables_pre0 = []
    for var in gorp_dict["variables"]:
        if "variable_type" not in var:
            var["variable_type"] = "env_var"
        if "protected" not in var:
            var["protected"] = False
        if "masked" not in var:
            var["masked"] = False
        if "raw" not in var:
            var["raw"] = False
        if "environment_scope" not in var:
            var["environment_scope"] = "*"
        gorp_dict_variables_pre0.append(var)

    # Expand quick key_values sets, pre1 before expanding environment_scope
    gorp_dict_variables_pre1 = []
    for var in gorp_dict_variables_pre0:
        if "key_values" in var:
            for k, v in var["key_values"].items():
                gorp_dict_variables_pre1.append(
                    {
                        "variable_type": var["variable_type"],
                        "protected": var["protected"],
                        "masked": var["masked"],
                        "raw": var["raw"],
                        "environment_scope": var["environment_scope"],
                        "key": k,
                        "value": v
                    }
                )
        else:
            gorp_dict_variables_pre1.append(var)

    # Expand environment_scope if it is a list
    gorp_dict_variables = []
    for var in gorp_dict_variables_pre1:
        if isinstance(var["environment_scope"], list):
            for env_scope in var["environment_scope"]:
                gorp_dict_variables.append(
                    {
                        "variable_type": var["variable_type"],
                        "protected": var["protected"],
                        "masked": var["masked"],
                        "raw": var["raw"],
                        "environment_scope": env_scope,
                        "key": var["key"],
                        "value": var["value"]
                    }
                )
        else:
            gorp_dict_variables.append(var)

    # If variables_from_files is set, load variables from files
    if "variables_from_files" in gorp_dict:

        for var_file in gorp_dict["variables_from_files"]:

            # Load variables from file
            var_file_dict = load_yaml("{0}".format(var_file), logger)
            if var_file_dict is None:
                raise Exception("Config file error or missing: {0}".format(var_file))

            # Expand defaults in var_file_dict to var_file_dict_expanded_pre0
            var_file_dict_expanded_pre0 = []
            for var in var_file_dict:
                if "variable_type" not in var:
                    var["variable_type"] = "env_var"
                if "protected" not in var:
                    var["protected"] = False
                if "masked" not in var:
                    var["masked"] = False
                if "raw" not in var:
                    var["raw"] = False
                if "environment_scope" not in var:
                    var["environment_scope"] = "*"
                var_file_dict_expanded_pre0.append(var)

            # Expand quick key_values sets in variables from file, pre1 before expanding environment_scope
            var_file_dict_expanded_pre1 = []
            for var in var_file_dict_expanded_pre0:
                if "key_values" in var:
                    for k, v in var["key_values"].items():
                        var_file_dict_expanded_pre1.append(
                            {
                                "variable_type": var["variable_type"],
                                "protected": var["protected"],
                                "masked": var["masked"],
                                "raw": var["raw"],
                                "environment_scope": var["environment_scope"],
                                "key": k,
                                "value": v
                            }
                        )
                else:
                    var_file_dict_expanded_pre1.append(var)

            # Expand environment_scope if it is a list
            var_file_dict_expanded = []
            for var in var_file_dict_expanded_pre1:
                if isinstance(var["environment_scope"], list):
                    for env_scope in var["environment_scope"]:
                        var_file_dict_expanded.append(
                            {
                                "variable_type": var["variable_type"],
                                "protected": var["protected"],
                                "masked": var["masked"],
                                "raw": var["raw"],
                                "environment_scope": env_scope,
                                "key": var["key"],
                                "value": var["value"]
                            }
                        )
                else:
                    var_file_dict_expanded.append(var)

            # Add var_file_dict_expanded items to gorp_dict_variables only if the same item with key, environment_scope is not already in gorp_dict_variables
            for var in var_file_dict_expanded:
                if not any(v["key"] == var["key"] and v["environment_scope"] == var["environment_scope"] for v in gorp_dict_variables):
                    gorp_dict_variables.append(var)

    # Normalize boolean values value field in gorp_dict_variables to string as gitlab returns - lowercase string
    for var in gorp_dict_variables:
        if str(var["value"]) == "True":
            var["value"] = "true"
        elif str(var["value"]) == "False":
            var["value"] = "false"

    # Get and print diff between existing and defined in yaml vars

    old_gorp_variables = gorp.variables.list(get_all=True)

    for var in gorp_dict_variables:
        var_found = False
        for gorp_var in old_gorp_variables:
            if gorp_var.environment_scope == var["environment_scope"] and gorp_var.key == var["key"]:
                var_found = True
                # Compare existing vars with yaml vars
                # If any difference, print
                if (
                    (gorp_var.value != str(var["value"]) and not (gorp_var.value is None and var["value"] is None))
                    or
                    gorp_var.variable_type != var["variable_type"]
                    or
                    gorp_var.protected != var["protected"]
                    or
                    gorp_var.masked != var["masked"]
                    or
                    gorp_var.raw != var["raw"]
                ):
                    print("changed: {scope} / {var}:".format(scope=var["environment_scope"], var=var["key"]))
                    # Print old -> new
                    if gorp_var.value != str(var["value"]) and not (gorp_var.value is None and var["value"] is None):
                        print("  value: {old} -> {new}".format(old=gorp_var.value, new=var["value"]))
                    if gorp_var.variable_type != var["variable_type"]:
                        print("  variable_type: {old} -> {new}".format(old=gorp_var.variable_type, new=var["variable_type"]))
                    if gorp_var.protected != var["protected"]:
                        print("  protected: {old} -> {new}".format(old=gorp_var.protected, new=var["protected"]))
                    if gorp_var.masked != var["masked"]:
                        print("  masked: {old} -> {new}".format(old=gorp_var.masked, new=var["masked"]))
                    if gorp_var.raw != var["raw"]:
                        print("  raw: {old} -> {new}".format(old=gorp_var.raw, new=var["raw"]))
        if not var_found:
            print("new: {scope} / {var}".format(scope=var["environment_scope"], var=var["key"]))
            print("  value: {value}".format(value=var["value"]))
            print("  variable_type: {variable_type}".format(variable_type=var["variable_type"]))
            print("  protected: {protected}".format(protected=var["protected"]))
            print("  masked: {masked}".format(masked=var["masked"]))
            print("  raw: {raw}".format(raw=var["raw"]))

    # Check vars to delete
    for gorp_var in old_gorp_variables:
        var_found = False
        for var in gorp_dict_variables:
            if gorp_var.environment_scope == var["environment_scope"] and gorp_var.key == var["key"]:
                var_found = True
        if not var_found:
            print("deleted: {scope} / {var}".format(scope=gorp_var.environment_scope, var=gorp_var.key))
            print("  value: {value}".format(value=gorp_var.value))
            print("  variable_type: {variable_type}".format(variable_type=gorp_var.variable_type))
            print("  protected: {protected}".format(protected=gorp_var.protected))
            print("  masked: {masked}".format(masked=gorp_var.masked))
            print("  raw: {raw}".format(raw=gorp_var.raw))

    # Check apply_variables_dry_run
    if args.apply_variables_dry_run:

        # Do nothing
        logger.warning("--apply-variables-dry-run is used, doing nothing")

    # Check variables_clean_all_before_set
    elif variables_clean_all_before_set:

        # Use multithreading to speed up
        with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENT_MAX_WORKERS) as executor:

            # There is a bug (at least at python-gitlab 3.14+):
            # gitlab.exceptions.GitlabDeleteError: 409: There are multiple variables with provided parameters. Please use 'filter[environment_scope]'
            # So delete via direct API call using requests

            # Create requests session to reuse request connection
            with requests.Session() as session:

                session.headers.update({"PRIVATE-TOKEN": GL_ADMIN_PRIVATE_TOKEN})

                for gorp_var in gorp.variables.list(get_all=True):

                    # Different API call for group and project
                    if gorp_kind == "group":
                        executor.submit(
                            session.delete, "{gitlab_url}/api/v4/groups/{path_encoded}/variables/{key}?filter%5Benvironment_scope%5D={environment_scope}".format(
                                gitlab_url=yaml_dict["gitlab"]["url"],
                                path_encoded=gorp_dict["path"].replace("/", "%2F"),
                                key=gorp_var.key,
                                environment_scope=gorp_var.environment_scope.replace("*", "%2A")
                            )
                        )
                    elif gorp_kind == "project":
                        executor.submit(
                            session.delete, "{gitlab_url}/api/v4/projects/{path_with_namespace_encoded}/variables/{key}?filter%5Benvironment_scope%5D={environment_scope}".format(
                                gitlab_url=yaml_dict["gitlab"]["url"],
                                path_with_namespace_encoded=gorp.path_with_namespace.replace("/", "%2F"),
                                key=gorp_var.key,
                                environment_scope=gorp_var.environment_scope.replace("*", "%2A")
                            )
                        )

                    logger.info("Deleted var {scope} / {var} because of variables_clean_all_before_set".format(scope=gorp_var.environment_scope, var=gorp_var.key))

            # Ensure all threads are done
            executor.shutdown(wait=True)

        # Define a function to use in multithreading
        def create_var(var):
            try:
                gorp.variables.create(var)
            except gitlab.exceptions.GitlabCreateError as e:
                logger.error("Error creating var {scope} / {var}, but the script continues".format(scope=var["environment_scope"], var=var["key"]))
                logger.error(e)
                if var["masked"] and (" " in var["value"] or "," in var["value"]):
                    logger.error("Masked var {scope} / {var} has space or comma in value, so it is not created".format(scope=var["environment_scope"], var=var["key"]))

        # Just add all vars from scratch

        # Use multithreading to speed up
        with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENT_MAX_WORKERS) as executor:

            # Create vars for the env scope
            for var in gorp_dict_variables:
                var_dict = {
                    "key": var["key"],
                    "value": var["value"],
                    "variable_type": var["variable_type"],
                    "protected": var["protected"],
                    "masked": var["masked"],
                    "raw": var["raw"],
                    "environment_scope": var["environment_scope"]
                }
                executor.submit(create_var, var_dict)
                logger.info("Var {scope} / {var} created".format(scope=var["environment_scope"], var=var["key"]))

        # Ensure all threads are done
        executor.shutdown(wait=True)

    else:

        # We cannot update vars as key for update is not scope safe, so we delete first if var state is not as needed
        old_gorp_variables = gorp.variables.list(get_all=True)
        for var in gorp_dict_variables:
            for gorp_var in old_gorp_variables:
                if gorp_var.environment_scope == var["environment_scope"] and gorp_var.key == var["key"]:
                    if (
                        gorp_var.value != str(var["value"])
                        or
                        gorp_var.variable_type != var["variable_type"]
                        or
                        gorp_var.protected != var["protected"]
                        or
                        gorp_var.masked != var["masked"]
                        or
                        gorp_var.raw != var["raw"]
                    ):
                        # gorp_var.delete()
                        # There is a bug (at least at python-gitlab 2.5.0):
                        # gitlab.exceptions.GitlabDeleteError: 409: There are multiple variables with provided parameters. Please use 'filter[environment_scope]'
                        # So delete via direct curl API call

                        # Different API call for group and project
                        if gorp_kind == "group":
                            script = textwrap.dedent(
                                """
                                curl --request DELETE \
                                        --header "PRIVATE-TOKEN: {private_token}" \
                                        "{gitlab_url}/api/v4/groups/{path_encoded}/variables/{key}?filter%5Benvironment_scope%5D={environment_scope}"
                                """
                            ).format(
                                gitlab_url=yaml_dict["gitlab"]["url"],
                                private_token=GL_ADMIN_PRIVATE_TOKEN,
                                path_encoded=gorp_dict["path"].replace("/", "%2F"),
                                key=var["key"],
                                environment_scope=var["environment_scope"].replace("*", "%2A")
                            )
                        elif gorp_kind == "project":
                            script = textwrap.dedent(
                                """
                                curl --request DELETE \
                                        --header "PRIVATE-TOKEN: {private_token}" \
                                        "{gitlab_url}/api/v4/projects/{path_with_namespace_encoded}/variables/{key}?filter%5Benvironment_scope%5D={environment_scope}"
                                """
                            ).format(
                                gitlab_url=yaml_dict["gitlab"]["url"],
                                private_token=GL_ADMIN_PRIVATE_TOKEN,
                                path_with_namespace_encoded=gorp.path_with_namespace.replace("/", "%2F"),
                                key=var["key"],
                                environment_scope=var["environment_scope"].replace("*", "%2A")
                            )

                        logger.info("Running bash script:")
                        logger.info(script)
                        process = subprocess.run(script, shell=True, universal_newlines=True, check=False, executable="/bin/bash", stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        if process.returncode:
                            logger.error("Check stdout:")
                            logger.error(process.stdout)
                            logger.error("Check stderr:")
                            logger.error(process.stderr)
                            raise SubprocessRunError("Subprocess run failed")
                        else:
                            logger.info("Check stdout:")
                            logger.info(process.stdout)
                            logger.info("Check stderr:")
                            logger.info(process.stderr)
                        logger.info("Var {scope} / {var} did not match yaml, deleted to be updated".format(scope=var["environment_scope"], var=var["key"]))

        # Adding is scope safe, so add all missing vars
        old_gorp_variables = gorp.variables.list(get_all=True)
        for var in gorp_dict_variables:
            if not any(gorp_var.environment_scope == var["environment_scope"] and gorp_var.key == var["key"] for gorp_var in old_gorp_variables):
                var_dict = {
                    "key": var["key"],
                    "value": var["value"],
                    "variable_type": var["variable_type"],
                    "protected": var["protected"],
                    "masked": var["masked"],
                    "raw": var["raw"],
                    "environment_scope": var["environment_scope"]
                }
                try:
                    gorp.variables.create(var_dict)
                except gitlab.exceptions.GitlabCreateError as e:
                    logger.error("Error creating var {scope} / {var}, but the script continues".format(scope=var["environment_scope"], var=var["key"]))
                    logger.error(e)
                    if var["masked"] and (" " in var["value"] or "," in var["value"]):
                        logger.error("Masked var {scope} / {var} has space or comma in value, so it is not created".format(scope=var["environment_scope"], var=var["key"]))
                logger.info("Var {scope} / {var} created".format(scope=var["environment_scope"], var=var["key"]))

# Main

if __name__ == "__main__":

    # Set parser and parse args
    parser = argparse.ArgumentParser(description='{LOGO} functions.'.format(LOGO=LOGO))
    parser.add_argument("--debug", dest="debug", help="enable debug", action="store_true")
    parser.add_argument("--git-push", dest="git_push", help="push after commit", action="store_true")
    parser.add_argument("--dry-run-gitlab", dest="dry_run_gitlab", help="no new objects created in gitlab", action="store_true")
    parser.add_argument("--yaml", dest="yaml", help="use file FILE instead of default projects.yaml", nargs=1, metavar=("FILE"))
    #parser.add_argument("--ignore-db", dest="ignore_db", help="ignore connect to db if do not use specific options", action="store_true")
    parser.add_argument("--variables-clean-all-before-set", dest="variables_clean_all_before_set", help="delete all variables before setting, useful to clean garbage", action="store_true")
    parser.add_argument("--apply-variables-dry-run", dest="apply_variables_dry_run", help="together with --apply-variables leads to just show the diff between existing and defined in yaml vars without applying", action="store_true")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--setup-projects", dest="setup_projects", help="ensure projects created in GitLab, their settings setup", action="store_true")
    group.add_argument("--dump-projects", dest="dump_projects", help="dump project settings", action="store_true")
    group.add_argument("--template-projects", dest="template_projects", help="update projects git repos from template using current user git creds", action="store_true")
    group.add_argument("--bulk-delete-tags-in-projects", dest="bulk_delete_tags_in_projects", help="bulk delete tags in projects", action="store_true")
    group.add_argument("--setup-groups", dest="setup_groups", help="ensure groups created in GitLab, their settings setup", action="store_true")
    group.add_argument("--dump-groups", dest="dump_groups", help="dump group settings", action="store_true")
    group.add_argument("--apply-variables", dest="apply_variables", help="apply only variables for all groups and projects in yaml which already must exist, always cleans vars before apply", action="store_true")
    args = parser.parse_args()

    # Set logger and console debug
    if args.debug:
        logger = set_logger(logging.DEBUG, LOG_DIR, LOG_FILE)
    else:
        logger = set_logger(logging.WARNING, LOG_DIR, LOG_FILE)

    GL_ADMIN_PRIVATE_TOKEN = os.environ.get("GL_ADMIN_PRIVATE_TOKEN")
    if GL_ADMIN_PRIVATE_TOKEN is None:
        raise Exception("Env var GL_ADMIN_PRIVATE_TOKEN missing")

    # As there are no options that need db hack, always ignore db now
    args.ignore_db = True

    if not (args.ignore_db or args.apply_variables):

        PG_DB_HOST = os.environ.get("PG_DB_HOST")
        if PG_DB_HOST is None:
            raise Exception("Env var PG_DB_HOST missing")

        PG_DB_NAME = os.environ.get("PG_DB_NAME")
        if PG_DB_NAME is None:
            raise Exception("Env var PG_DB_NAME missing")

        PG_DB_USER = os.environ.get("PG_DB_USER")
        if PG_DB_USER is None:
            raise Exception("Env var PG_DB_USER missing")

        PG_DB_PASS = os.environ.get("PG_DB_PASS")
        if PG_DB_PASS is None:
            raise Exception("Env var PG_DB_PASS missing")

    # Catch exception to logger

    try:

        logger.info("Starting {LOGO}".format(LOGO=LOGO))

        # Chdir to work dir
        os.chdir(WORK_DIR)

        # Read projects
        if args.yaml is not None:
            yaml_dict = load_yaml("{0}".format(args.yaml[0]), logger)
            if yaml_dict is None:
                raise Exception("Config file error or missing: {0}".format(args.yaml[0]))
        else:
            yaml_dict = load_yaml("{0}/{1}".format(WORK_DIR, PROJECTS_YAML), logger)
            if yaml_dict is None:
                raise Exception("Config file error or missing: {0}/{1}".format(WORK_DIR, PROJECTS_YAML))

        # Connect to PG
        if not (args.ignore_db or args.apply_variables):
            dsn = "host={} dbname={} user={} password={}".format(PG_DB_HOST, PG_DB_NAME, PG_DB_USER, PG_DB_PASS)
            conn = psycopg2.connect(dsn)

        # Do tasks

        if args.apply_variables:

            # Connect to GitLab
            gl = gitlab.Gitlab(yaml_dict["gitlab"]["url"], private_token=GL_ADMIN_PRIVATE_TOKEN)
            gl.auth()

            # For groups
            if "groups" in yaml_dict:

                for group_dict in yaml_dict["groups"]:

                    # Check group active
                    if group_dict["active"]:

                        # Get GitLab group
                        logger.info("Getting group {group}".format(group=group_dict["path"]))
                        group = gl.groups.get(group_dict["path"])
                        old_group_dict = group.asdict()

                        # Set needed group params
                        if not args.dry_run_gitlab:

                            # CI Variables
                            if "variables" in group_dict:

                                logger.info("Found group yaml definition for vars: {variables}".format(variables=group_dict["variables"]))

                                # Always clean all vars before set
                                variables_clean_all_before_set = True

                                # Call function
                                apply_vars_gorp("group", yaml_dict, group, group_dict, variables_clean_all_before_set, logger)

                            # Save
                            group.save()
                            new_group_dict = group.asdict()
                            if old_group_dict != new_group_dict:
                                print(DeepDiff(old_group_dict, new_group_dict).pretty())

                        logger.info("Group {group} settings:".format(group=group_dict["path"]))
                        logger.info(group)

            # For projects
            if "projects" in yaml_dict:

                for project_dict in yaml_dict["projects"]:

                    # Check project active
                    if project_dict["active"]:

                        # Get GitLab project
                        logger.info("Getting project {project}".format(project=project_dict["path"]))
                        project = gl.projects.get(project_dict["path"])
                        old_project_dict = project.asdict()

                        # Set needed project params
                        if not args.dry_run_gitlab:

                            # CI Variables
                            if "variables" in project_dict and not ("jobs_enabled" in project_dict and project_dict["jobs_enabled"] is False):

                                logger.info("Found project yaml definition for vars: {variables}".format(variables=project_dict["variables"]))

                                # Always clean all vars before set
                                variables_clean_all_before_set = True

                                # Call function
                                apply_vars_gorp("project", yaml_dict, project, project_dict, variables_clean_all_before_set, logger)

                            # Save
                            project.save()
                            new_project_dict = project.asdict()
                            if old_project_dict != new_project_dict:
                                print(DeepDiff(old_project_dict, new_project_dict).pretty())

                        logger.info("Project {project} settings:".format(project=project_dict["path"]))
                        logger.info(project)

        if args.dump_groups:

            gl = gitlab.Gitlab(yaml_dict["gitlab"]["url"], private_token=GL_ADMIN_PRIVATE_TOKEN)
            gl.auth()

            # For groups
            for group_dict in yaml_dict["groups"]:
                if group_dict["active"]:
                    # Get GitLab group
                    logger.info("Getting group {group}".format(group=group_dict["path"]))
                    group = gl.groups.get(group_dict["path"])
                    logger.info("Group {group} settings:".format(group=group_dict["path"]))
                    # Convert asdict to json to print
                    print_json(json.dumps(group.asdict()))

        if args.setup_groups:

            # Connect to GitLab
            gl = gitlab.Gitlab(yaml_dict["gitlab"]["url"], private_token=GL_ADMIN_PRIVATE_TOKEN)
            gl.auth()

            # For groups
            for group_dict in yaml_dict["groups"]:

                logger.info("Found group yaml definition: {group}".format(group=group_dict))

                # Check group active
                if group_dict["active"]:

                    # Get GitLab group
                    try:
                        logger.info("Checking group {group}".format(group=group_dict["path"]))
                        group = gl.groups.get(group_dict["path"])
                        old_group_dict = group.asdict()
                    except gitlab.exceptions.GitlabGetError as e:

                        # Create if not found
                        logger.info("Group {group}, creating".format(group=group_dict["path"]))

                        group_path = group_dict["path"].split("/")[-1]
                        # Search for the parent group
                        # Split and join up to last slash group path
                        parent_group_path = "/".join(group_dict["path"].split("/")[:-1])
                        if parent_group_path != "":
                            parent_group = gl.groups.get(parent_group_path)
                            logger.info("Found parent group ID: {id}, name: {group}".format(group=parent_group.full_name, id=parent_group.id))
                            # Create group in parent
                            if not args.dry_run_gitlab:
                                group = gl.groups.create({'name': group_dict["name"], 'path': group_path, 'parent_id': parent_group.id})
                                old_group_dict = group.asdict()
                        else:
                            # Create group in root
                            if not args.dry_run_gitlab:
                                group = gl.groups.create({'name': group_dict["name"], 'path': group_path})
                                old_group_dict = group.asdict()

                    # Set needed group params
                    if not args.dry_run_gitlab:
                        group.name = group_dict["name"]
                        group.description = group_dict["description"]
                        group.visibility = group_dict["visibility"]

                        # Members
                        if "members" in group_dict:
                            for member in group_dict["members"]:
                                if "user" in member:
                                    user_id = gl.users.list(username=member["user"])[0].id
                                    logger.info("Found user ID: {id}, name: {user}".format(id=user_id, user=member["user"]))
                                    try:
                                        current_member = group.members.get(user_id)
                                        current_member.access_level = member["access_level"]
                                        current_member.save()
                                    except gitlab.exceptions.GitlabGetError as e:
                                        gl_member = group.members.create({'user_id': user_id, 'access_level': member["access_level"]})
                                        gl_member.save()
                                if "group" in member:
                                    group_id = gl.groups.get(member["group"]).id
                                    if not any(shared_group["group_id"] == group_id and shared_group["group_access_level"] == member["access_level"] for shared_group in group.shared_with_groups):
                                        # There is no method to change share, so if it is already shared - catch error and unshare+share
                                        try:
                                            group.share(group_id, member["access_level"])
                                        except gitlab.exceptions.GitlabCreateError as e:
                                            group.unshare(group_id)
                                            group.share(group_id, member["access_level"])
                        # CI Variables
                        if "variables" in group_dict:

                            # Check variables_clean_all_before_set
                            if args.variables_clean_all_before_set or ("variables_clean_all_before_set" in group_dict and group_dict["variables_clean_all_before_set"]):
                                variables_clean_all_before_set = True
                            else:
                                variables_clean_all_before_set = False

                            # Call function
                            apply_vars_gorp("group", yaml_dict, group, group_dict, variables_clean_all_before_set, logger)

                        # Save
                        group.save()
                        new_group_dict = group.asdict()
                        if old_group_dict != new_group_dict:
                            print(DeepDiff(old_group_dict, new_group_dict).pretty())

                    logger.info("Group {group} settings:".format(group=group_dict["path"]))
                    logger.info(group)

        if args.dump_projects:

            gl = gitlab.Gitlab(yaml_dict["gitlab"]["url"], private_token=GL_ADMIN_PRIVATE_TOKEN)
            gl.auth()

            # For projects
            for project_dict in yaml_dict["projects"]:
                if project_dict["active"]:
                    # Get GitLab project
                    logger.info("Getting project {project}".format(project=project_dict["path"]))
                    project = gl.projects.get(project_dict["path"])
                    logger.info("Project {project} settings:".format(project=project_dict["path"]))
                    # Convert asdict to json to print
                    print_json(json.dumps(project.asdict()))

        if args.setup_projects:

            # Connect to GitLab
            gl = gitlab.Gitlab(yaml_dict["gitlab"]["url"], private_token=GL_ADMIN_PRIVATE_TOKEN)
            gl.auth()

            # For projects
            for project_dict in yaml_dict["projects"]:

                logger.info("Found project yaml definition: {project}".format(project=project_dict))

                # Check project active
                if project_dict["active"]:

                    # Get GitLab project
                    try:
                        logger.info("Checking project {project}".format(project=project_dict["path"]))
                        project = gl.projects.get(project_dict["path"])
                        old_project_dict = project.asdict()
                    except gitlab.exceptions.GitlabGetError as e:
                        # Create if not found
                        logger.info("Project {project}, creating".format(project=project_dict["path"]))
                        # Search for the group
                        # Split and join up to last slash project path
                        group_full_path = "/".join(project_dict["path"].split("/")[:-1])
                        project_path = project_dict["path"].split("/")[-1]
                        group = gl.groups.get(group_full_path)
                        group_id = group.id
                        logger.info("Found group ID: {id}, name: {group}".format(group=group.full_name, id=group.id))
                        # Create project
                        if not args.dry_run_gitlab:
                            project = gl.projects.create({'name': project_dict["name"], 'namespace_id': group_id, 'path': project_path})
                            old_project_dict = project.asdict()
                            # Add first files on creating
                            f = project.files.create(
                                {
                                    'file_path': 'README.md',
                                    'branch': 'master',
                                    'content': project_dict["description"],
                                    'author_email': yaml_dict["gitlab"]["author_email"],
                                    'author_name': yaml_dict["gitlab"]["author_name"],
                                    'commit_message': 'Initial commit'
                                }
                            )

                    # Set needed project params
                    if not args.dry_run_gitlab:
                        project.name = project_dict["name"]
                        project.description = project_dict["description"]
                        project.visibility = project_dict["visibility"]
                        if "merge_method" in project_dict:
                            project.merge_method = project_dict["merge_method"]
                        if "squash_option" in project_dict:
                            project.squash_option = project_dict["squash_option"]
                        if "resolve_outdated_diff_discussions" in project_dict:
                            project.resolve_outdated_diff_discussions = project_dict["resolve_outdated_diff_discussions"]
                        if "only_allow_merge_if_pipeline_succeeds" in project_dict:
                            project.only_allow_merge_if_pipeline_succeeds = project_dict["only_allow_merge_if_pipeline_succeeds"]
                        if "only_allow_merge_if_all_discussions_are_resolved" in project_dict:
                            project.only_allow_merge_if_all_discussions_are_resolved = project_dict["only_allow_merge_if_all_discussions_are_resolved"]
                        if "shared_runners_enabled" in project_dict:
                            project.shared_runners_enabled = project_dict["shared_runners_enabled"]
                        if "issues_enabled" in project_dict:
                            project.issues_enabled = project_dict["issues_enabled"]
                        if "wiki_enabled" in project_dict:
                            project.wiki_enabled = project_dict["wiki_enabled"]
                        if "packages_enabled" in project_dict:
                            project.packages_enabled = project_dict["packages_enabled"]
                        if "approvals_before_merge" in project_dict:
                            project.approvals_before_merge = project_dict["approvals_before_merge"]
                        if "service_desk_enabled" in project_dict:
                            project.service_desk_enabled = project_dict["service_desk_enabled"]
                        if "auto_devops_enabled" in project_dict:
                            project.auto_devops_enabled = project_dict["auto_devops_enabled"]
                        if "container_registry_enabled" in project_dict:
                            project.container_registry_enabled = project_dict["container_registry_enabled"]
                        if "jobs_enabled" in project_dict:
                            project.jobs_enabled = project_dict["jobs_enabled"]
                        if "lfs_enabled" in project_dict:
                            project.lfs_enabled = project_dict["lfs_enabled"]
                        if "merge_requests_enabled" in project_dict:
                            project.merge_requests_enabled = project_dict["merge_requests_enabled"]
                        if "snippets_enabled" in project_dict:
                            project.snippets_enabled = project_dict["snippets_enabled"]
                        if "analytics_access_level" in project_dict:
                            project.analytics_access_level = project_dict["analytics_access_level"]
                        if "builds_access_level" in project_dict:
                            project.builds_access_level = project_dict["builds_access_level"]
                        if "forking_access_level" in project_dict:
                            project.forking_access_level = project_dict["forking_access_level"]
                        if "issues_access_level" in project_dict:
                            project.issues_access_level = project_dict["issues_access_level"]
                        if "merge_requests_access_level" in project_dict:
                            project.merge_requests_access_level = project_dict["merge_requests_access_level"]
                        if "operations_access_level" in project_dict:
                            project.operations_access_level = project_dict["operations_access_level"]
                        if "pages_access_level" in project_dict:
                            project.pages_access_level = project_dict["pages_access_level"]
                        if "requirements_access_level" in project_dict:
                            project.requirements_access_level = project_dict["requirements_access_level"]
                        if "snippets_access_level" in project_dict:
                            project.snippets_access_level = project_dict["snippets_access_level"]
                        if "wiki_access_level" in project_dict:
                            project.wiki_access_level = project_dict["wiki_access_level"]
                        if "repository_access_level" in project_dict:
                            project.repository_access_level = project_dict["repository_access_level"]
                            # Otherwise error
                            if project_dict["repository_access_level"] == "disabled":
                                project.merge_requests_access_level = "disabled"
                                project.builds_access_level = "disabled"
                        # Members
                        if "members" in project_dict:
                            for member in project_dict["members"]:
                                if "user" in member:
                                    user_id = gl.users.list(username=member["user"])[0].id
                                    logger.info("Found user ID: {id}, name: {user}".format(id=user_id, user=member["user"]))
                                    try:
                                        current_member = project.members.get(user_id)
                                        current_member.access_level = member["access_level"]
                                        current_member.save()
                                    except gitlab.exceptions.GitlabGetError as e:
                                        logger.info("User {user} not found in project {project}, adding".format(user=member["user"], project=project_dict["path"]))
                                        gl_member = project.members.create({'user_id': user_id, 'access_level': member["access_level"]})
                                        gl_member.save()
                                if "group" in member:
                                    group_id = gl.groups.get(member["group"]).id
                                    if not any(shared_group["group_id"] == group_id and shared_group["group_access_level"] == member["access_level"] for shared_group in project.shared_with_groups):
                                        # There is no method to change share, so if it is already shared - catch error and unshare+share
                                        try:
                                            project.share(group_id, member["access_level"])
                                        except gitlab.exceptions.GitlabCreateError as e:
                                            project.unshare(group_id)
                                            project.share(group_id, member["access_level"])
                        # Deploy keys
                        if "deploy_keys" in project_dict:
                            for deploy_key in project_dict["deploy_keys"]:
                                key = project.keys.create({'title': deploy_key["title"], 'key': deploy_key["key"]})

                        # Deploy tokens
                        if "deploy_tokens" in project_dict:
                            for deploy_token in project_dict["deploy_tokens"]:
                                project_id = project.id
                                token_needs_to_be_created = True

                                # Get only active tokens
                                response = requests.get(
                                    f'{yaml_dict["gitlab"]["url"]}/api/v4/projects/{project_id}/deploy_tokens?active=true',
                                    headers={'PRIVATE-TOKEN': GL_ADMIN_PRIVATE_TOKEN}
                                )
                                response = response.json()

                                # check token if active token exist
                                if response:
                                    for token in response:
                                        if token["name"] == deploy_token["name"]:
                                            token_needs_to_be_created = False
                                            break

                                if not token_needs_to_be_created:
                                    logger.info("Project {project} deploy token {token_name} already exists".format(project=project_dict["path"], token_name=deploy_token["name"]))
                                else:
                                    # create a token if it does not exist or is new
                                    data = {
                                        "name": deploy_token["name"],
                                        "scopes": deploy_token["scopes"]
                                    }

                                    response = requests.post(
                                        f'{yaml_dict["gitlab"]["url"]}/api/v4/projects/{project_id}/deploy_tokens/',
                                        headers={'PRIVATE-TOKEN': GL_ADMIN_PRIVATE_TOKEN},
                                        json=data
                                    )

                                    response = response.json()
                                    # Log response
                                    logger.info(f"Response: {response}")
                                    print("Project {project} deploy token added:".format(project=project_dict["path"]))
                                    print("---\nToken for {token_name}: {token}\n---".format(token=response["token"], token_name=deploy_token["name"]))

                        # Access tokens
                        if "access_tokens" in project_dict:
                            for access_token in project_dict["access_tokens"]:
                                project_id = project.id
                                token_needs_to_be_created = True

                                # Get only active tokens
                                response = requests.get(
                                    f'{yaml_dict["gitlab"]["url"]}/api/v4/projects/{project_id}/access_tokens?active=true',
                                    headers={'PRIVATE-TOKEN': GL_ADMIN_PRIVATE_TOKEN}
                                )
                                response = response.json()

                                # check token if active token exist
                                if response:
                                    for token in response:
                                        if token["name"] == access_token["name"]:
                                            token_needs_to_be_created = False
                                            break

                                if not token_needs_to_be_created:
                                    logger.info("Project {project} access token {token_name} already exists".format(project=project_dict["path"], token_name=access_token["name"]))
                                else:
                                    # create a token if it does not exist or is new
                                    data = {
                                        "name": access_token["name"],
                                        "scopes": access_token["scopes"],
                                        "access_level": access_token["access_level"],
                                        "expires_at": access_token["expires_at"]
                                    }

                                    response = requests.post(
                                        f'{yaml_dict["gitlab"]["url"]}/api/v4/projects/{project_id}/access_tokens/',
                                        headers={'PRIVATE-TOKEN': GL_ADMIN_PRIVATE_TOKEN},
                                        json=data
                                    )

                                    response = response.json()
                                    # Log response
                                    logger.info(f"Response: {response}")
                                    print("Project {project} access token added:".format(project=project_dict["path"]))
                                    print("---\nToken for {token_name}: {token}\n---".format(token=response["token"], token_name=access_token["name"]))

                        # MR approval rules
                        if "approvals_before_merge" in project_dict:
                            p_mras = project.approvals.get()
                            old_p_mras_dict = p_mras.asdict()
                            p_mras.approvals_before_merge = project_dict["approvals_before_merge"]
                            p_mras.save()
                            new_p_mras_dict = p_mras.asdict()
                            if old_p_mras_dict != new_p_mras_dict:
                                print(DeepDiff(old_p_mras_dict, new_p_mras_dict).pretty())
                        if "reset_approvals_on_push" in project_dict:
                            p_mras = project.approvals.get()
                            old_p_mras_dict = p_mras.asdict()
                            p_mras.reset_approvals_on_push = project_dict["reset_approvals_on_push"]
                            p_mras.save()
                            new_p_mras_dict = p_mras.asdict()
                            if old_p_mras_dict != new_p_mras_dict:
                                print(DeepDiff(old_p_mras_dict, new_p_mras_dict).pretty())
                        if "selective_code_owner_removals" in project_dict:
                            p_mras = project.approvals.get()
                            old_p_mras_dict = p_mras.asdict()
                            p_mras.selective_code_owner_removals = project_dict["selective_code_owner_removals"]
                            p_mras.save()
                            new_p_mras_dict = p_mras.asdict()
                            if old_p_mras_dict != new_p_mras_dict:
                                print(DeepDiff(old_p_mras_dict, new_p_mras_dict).pretty())
                        if "disable_overriding_approvers_per_merge_request" in project_dict:
                            p_mras = project.approvals.get()
                            old_p_mras_dict = p_mras.asdict()
                            p_mras.disable_overriding_approvers_per_merge_request = project_dict["disable_overriding_approvers_per_merge_request"]
                            p_mras.save()
                            new_p_mras_dict = p_mras.asdict()
                            if old_p_mras_dict != new_p_mras_dict:
                                print(DeepDiff(old_p_mras_dict, new_p_mras_dict).pretty())
                        if "merge_requests_author_approval" in project_dict:
                            p_mras = project.approvals.get()
                            old_p_mras_dict = p_mras.asdict()
                            p_mras.merge_requests_author_approval = project_dict["merge_requests_author_approval"]
                            p_mras.save()
                            new_p_mras_dict = p_mras.asdict()
                            if old_p_mras_dict != new_p_mras_dict:
                                print(DeepDiff(old_p_mras_dict, new_p_mras_dict).pretty())
                        if "merge_requests_disable_committers_approval" in project_dict:
                            p_mras = project.approvals.get()
                            old_p_mras_dict = p_mras.asdict()
                            p_mras.merge_requests_disable_committers_approval = project_dict["merge_requests_disable_committers_approval"]
                            p_mras.save()
                            new_p_mras_dict = p_mras.asdict()
                            if old_p_mras_dict != new_p_mras_dict:
                                print(DeepDiff(old_p_mras_dict, new_p_mras_dict).pretty())
                        if "require_password_to_approve" in project_dict:
                            p_mras = project.approvals.get()
                            old_p_mras_dict = p_mras.asdict()
                            p_mras.require_password_to_approve = project_dict["require_password_to_approve"]
                            p_mras.save()
                            new_p_mras_dict = p_mras.asdict()
                            if old_p_mras_dict != new_p_mras_dict:
                                print(DeepDiff(old_p_mras_dict, new_p_mras_dict).pretty())

                        # Skip outdated deployment jobs
                        if "skip_outdated_deployment_jobs" in project_dict:
                            project_id = project.id
                            data = {
                                'ci_forward_deployment_enabled': project_dict["skip_outdated_deployment_jobs"]
                            }
                            response = requests.put(
                                f'{yaml_dict["gitlab"]["url"]}/api/v4/projects/{project_id}',
                                headers={'PRIVATE-TOKEN': GL_ADMIN_PRIVATE_TOKEN},
                                json=data
                            )

                            logger.info(f'Project skip_outdated_deployment_jobs set via api to {project_dict["skip_outdated_deployment_jobs"]}')

                        # Squash settings
                        # This was added to the API finally
                        # Just as and old sql hack example left as comment
                        # cur = conn.cursor()
                        # sql = "UPDATE project_settings SET squash_option={squash_option} WHERE project_id = {id}".format(squash_option=squash_option, id=project.id)
                        # try:
                        #     cur.execute(sql)
                        #     logger.info("Query execution status:")
                        #     logger.info(cur.statusmessage)
                        #     conn.commit()
                        # except Exception as e:
                        #     raise Exception("Caught exception on query execution")
                        # cur.close()
                        # logger.info("Project squash_commits_when_merging set via db to {squash_option}".format(squash_option=project_dict["squash_commits_when_merging"]))
                        if "squash_commits_when_merging" in project_dict:
                            logger.warning('squash_commits_when_merging is deprecated. Use squash_option')

                        # Protected branches
                        if "protected_branches" in project_dict:
                            for branch in project_dict["protected_branches"]:

                                if any(project_branch.name == branch["name"] for project_branch in project.protectedbranches.list(get_all=True)):
                                    p_branch = project.protectedbranches.get(branch["name"])
                                    old_p_branch = project.protectedbranches.get(branch["name"]).asdict()
                                    p_branch.delete()
                                else:
                                    old_p_branch = {}

                                branch_dict = {
                                    "name": branch["name"],
                                    "push_access_level": branch["push_access_level"],
                                    "merge_access_level": branch["merge_access_level"],
                                    "allow_force_push": default(lambda: branch["allow_force_push"], False),
                                    "code_owner_approval_required": branch["code_owner_approval_required"]
                                }

                                if "allowed_to_merge" in branch:
                                    branch_dict["allowed_to_merge"] = []
                                    for user_or_group in branch["allowed_to_merge"]:
                                        if "user" in user_or_group:
                                            user_id = gl.users.list(username=user_or_group["user"])[0].id
                                            logger.info("Found user ID: {id}, name: {user}".format(id=user_id, user=user_or_group["user"]))
                                            branch_dict["allowed_to_merge"].append({"user_id": user_id})
                                        if "group" in user_or_group:
                                            group_id = gl.groups.get(user_or_group["group"]).id
                                            logger.info("Found group ID: {id}, name: {group}".format(id=group_id, group=user_or_group["group"]))
                                            branch_dict["allowed_to_merge"].append({"group_id": group_id})

                                if "allowed_to_push" in branch:
                                    branch_dict["allowed_to_push"] = []
                                    for user_or_group in branch["allowed_to_push"]:
                                        if "user" in user_or_group:
                                            user_id = gl.users.list(username=user_or_group["user"])[0].id
                                            logger.info("Found user ID: {id}, name: {user}".format(id=user_id, user=user_or_group["user"]))
                                            branch_dict["allowed_to_push"].append({"user_id": user_id})
                                        if "group" in user_or_group:
                                            group_id = gl.groups.get(user_or_group["group"]).id
                                            logger.info("Found group ID: {id}, name: {group}".format(id=group_id, group=user_or_group["group"]))
                                            branch_dict["allowed_to_push"].append({"group_id": group_id})

                                project.protectedbranches.create(branch_dict)
                                new_p_branch = project.protectedbranches.get(branch["name"]).asdict()
                                diff = DeepDiff(old_p_branch, new_p_branch, exclude_regex_paths=[r"root\[.+\]\[.+\]\['id'\]", r"root\['id'\]"])
                                if diff:
                                    print("Protected branch \"{branch_name}\" config diff:".format(branch_name=branch["name"]))
                                    print("---")
                                    print(diff.pretty())
                                    print("---")

                            project.save()

                        # Protected tags
                        if "protected_tags" in project_dict:
                            for tag in project_dict["protected_tags"]:

                                if any(project_tag.name == tag["name"] for project_tag in project.protectedtags.list(get_all=True)):
                                    p_tag = project.protectedtags.get(tag["name"])
                                    old_p_tag = project.protectedtags.get(tag["name"]).asdict()
                                    p_tag.delete()
                                else:
                                    old_p_tag = {}

                                tag_dict = {
                                    "name": tag["name"],
                                    "create_access_level": tag["create_access_level"]
                                }

                                if "allowed_to_create" in tag:
                                    tag_dict["allowed_to_create"] = []
                                    for user_or_group in tag["allowed_to_create"]:
                                        if "user" in user_or_group:
                                            user_id = gl.users.list(username=user_or_group["user"])[0].id
                                            logger.info("Found user ID: {id}, name: {user}".format(id=user_id, user=user_or_group["user"]))
                                            tag_dict["allowed_to_create"].append({"user_id": user_id})
                                        if "group" in user_or_group:
                                            group_id = gl.groups.get(user_or_group["group"]).id
                                            logger.info("Found group ID: {id}, name: {group}".format(id=group_id, group=user_or_group["group"]))
                                            tag_dict["allowed_to_create"].append({"group_id": group_id})

                                project.protectedtags.create(tag_dict)
                                new_p_tag = project.protectedtags.get(tag["name"]).asdict()
                                diff = DeepDiff(old_p_tag, new_p_tag, exclude_regex_paths=[r"root\[.+\]\[.+\]\['id'\]", r"root\['id'\]"])
                                if diff:
                                    print("Protected tag \"{tag_name}\" config diff:".format(tag_name=tag["name"]))
                                    print("---")
                                    print(diff.pretty())
                                    print("---")

                            project.save()

                        # MR approval rules (should be done after branch protection reset)
                        if "merge_request_approval_rules" in project_dict:
                            # Empty list before setting
                            for mrar in project.approvalrules.list(get_all=True):
                                if mrar.name == 'All Members':
                                    continue
                                mrar.delete()
                            for rule in project_dict["merge_request_approval_rules"]:

                                g_ids = []
                                for gr in rule["groups"]:
                                    group = gl.groups.get(gr)
                                    logger.info("Found group ID: {id}, name: {group}".format(group=group.full_name, id=group.id))
                                    g_ids.append(group.id)

                                project.approvalrules.create(
                                    {
                                        'name': rule["name"],
                                        'approvals_required': rule["approvals_required"],
                                        'rule_type': 'regular',
                                        'protected_branch_ids': [project.protectedbranches.get(rule["branch"]).id],
                                        'group_ids': g_ids
                                    }
                                )

                        # Runners
                        if "specific_runners_enabled" in project_dict:
                            for runner_to_add in project_dict["specific_runners_enabled"]:
                                for runner in gl.runners.list(get_all=True):
                                    if runner.description == runner_to_add:
                                        if not any(added_runner.description == runner_to_add for added_runner in project.runners.list(get_all=True)):
                                            project.runners.create({'runner_id': runner.id})

                        # Protected envs
                        if "protected_environments" in project_dict and not ("jobs_enabled" in project_dict and project_dict["jobs_enabled"] is False):
                            for env in project_dict["protected_environments"]:
                                # Create env first
                                if not any(p_env.name == env["name"] for p_env in project.environments.list(get_all=True)):
                                    project.environments.create({'name': env["name"]})
                                # Protect with curl (python not yet supported)
                                data = {
                                    "name": env["name"],
                                    "deploy_access_levels": [
                                        {
                                            "access_level": env["deploy_access_level"]
                                        }
                                    ]
                                }
                                script = textwrap.dedent(
                                    """
                                    curl -sS --request POST \
                                            --header "PRIVATE-TOKEN: {private_token}" \
                                            --header "Content-Type: application/json" \
                                            --data '{data}' \
                                            "{gitlab_url}/api/v4/projects/{path_with_namespace_encoded}/protected_environments"
                                    """
                                ).format(
                                    gitlab_url=yaml_dict["gitlab"]["url"],
                                    private_token=GL_ADMIN_PRIVATE_TOKEN,
                                    path_with_namespace_encoded=project.path_with_namespace.replace("/", "%2F"),
                                    data=json.dumps(data)
                                )
                                logger.info("Running bash script:")
                                logger.info(script)
                                process = subprocess.run(script, shell=True, universal_newlines=True, check=False, executable="/bin/bash", stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                                if process.returncode:
                                    logger.error("Check stdout:")
                                    logger.error(process.stdout)
                                    logger.error("Check stderr:")
                                    logger.error(process.stderr)
                                    raise SubprocessRunError("Subprocess run failed")
                                else:
                                    logger.info("Check stdout:")
                                    logger.info(process.stdout)
                                    logger.info("Check stderr:")
                                    logger.info(process.stderr)

                        # CI Variables
                        if "variables" in project_dict and not ("jobs_enabled" in project_dict and project_dict["jobs_enabled"] is False):

                            # Check variables_clean_all_before_set
                            if args.variables_clean_all_before_set or ("variables_clean_all_before_set" in project_dict and project_dict["variables_clean_all_before_set"]):
                                variables_clean_all_before_set = True
                            else:
                                variables_clean_all_before_set = False

                            # Call function
                            apply_vars_gorp("project", yaml_dict, project, project_dict, variables_clean_all_before_set, logger)

                        # Push Rules
                        if "push_rules" in project_dict:

                            # Get existing rules, None if not exist
                            pr = project.pushrules.get()
                            if pr is None:
                                old_pr_dict = {}
                                # At least one option is required to create, use commit_committer_check
                                project.pushrules.create({'commit_committer_check': project_dict["push_rules"]["commit_committer_check"]})
                                pr = project.pushrules.get()
                            else:
                                old_pr_dict = pr.asdict()

                            # Set other params
                            pr.commit_committer_check = project_dict["push_rules"]["commit_committer_check"]
                            if "commit_committer_name_check" in project_dict["push_rules"]:
                                pr.commit_committer_name_check = project_dict["push_rules"]["commit_committer_name_check"]
                            if "reject_unsigned_commits" in project_dict["push_rules"]:
                                pr.reject_unsigned_commits = project_dict["push_rules"]["reject_unsigned_commits"]
                            if "deny_delete_tag" in project_dict["push_rules"]:
                                pr.deny_delete_tag = project_dict["push_rules"]["deny_delete_tag"]
                            if "member_check" in project_dict["push_rules"]:
                                pr.member_check = project_dict["push_rules"]["member_check"]
                            if "prevent_secrets" in project_dict["push_rules"]:
                                pr.prevent_secrets = project_dict["push_rules"]["prevent_secrets"]
                            if "commit_message_regex" in project_dict["push_rules"]:
                                pr.commit_message_regex = project_dict["push_rules"]["commit_message_regex"]
                            if "commit_message_negative_regex" in project_dict["push_rules"]:
                                pr.commit_message_negative_regex = project_dict["push_rules"]["commit_message_negative_regex"]
                            if "branch_name_regex" in project_dict["push_rules"]:
                                pr.branch_name_regex = project_dict["push_rules"]["branch_name_regex"]
                            if "author_email_regex" in project_dict["push_rules"]:
                                pr.author_email_regex = project_dict["push_rules"]["author_email_regex"]
                            if "file_name_regex" in project_dict["push_rules"]:
                                pr.file_name_regex = project_dict["push_rules"]["file_name_regex"]
                            if "max_file_size" in project_dict["push_rules"]:
                                pr.max_file_size = project_dict["push_rules"]["max_file_size"]
                            pr.save()
                            new_pr_dict = pr.asdict()
                            if old_pr_dict != new_pr_dict:
                                print(DeepDiff(old_pr_dict, new_pr_dict).pretty())

                        # Settings available only via GraphQL

                        # Create a GraphQL client using the defined transport, connecting to the GitLab instance
                        graphql_transport = RequestsHTTPTransport(url=yaml_dict["gitlab"]["url"] + "/api/graphql", headers={"PRIVATE-TOKEN": GL_ADMIN_PRIVATE_TOKEN}, use_json=True)
                        graphql_client = Client(transport=graphql_transport, fetch_schema_from_transport=True)

                        # cicd:token_access_limit_access_to_this_project
                        if "cicd" in project_dict and "token_access_limit_access_to_this_project" in project_dict["cicd"]:
                            # Set ProjectCiCdSetting
                            # https://docs.gitlab.com/ee/api/graphql/reference/index.html#projectcicdsetting
                            # https://docs.gitlab.com/ee/api/graphql/reference/index.html#mutationprojectcicdsettingsupdate
                            # https://docs.gitlab.com/ee/api/graphql/getting_started.html#update-project-settings
                            mutation = gql(
                                """
                                mutation cicd_token_access_limit_access_to_this_project($fullPath: ID!, $inboundJobTokenScopeEnabled: Boolean!) {
                                  projectCiCdSettingsUpdate(input: {fullPath: $fullPath, inboundJobTokenScopeEnabled: $inboundJobTokenScopeEnabled}) {
                                    errors
                                    ciCdSettings {
                                      inboundJobTokenScopeEnabled
                                    }
                                  }
                                }
                                """
                            )
                            mutation_variables = {
                                "fullPath": project.path_with_namespace,
                                "inboundJobTokenScopeEnabled": project_dict["cicd"]["token_access_limit_access_to_this_project"]
                            }
                            graphql_result = graphql_client.execute(mutation, variable_values=mutation_variables)
                            # Log result
                            logger.info("Project {project} cicd:token_access_limit_access_to_this_project GraphQL result:".format(project=project_dict["path"]))
                            logger.info(graphql_result)

                        # cicd:projects_with_access
                        if "cicd" in project_dict and "projects_with_access" in project_dict["cicd"]:
                            # Add Projects with access, Delete not yet supported
                            # https://docs.gitlab.com/ee/api/graphql/reference/index.html#mutationcijobtokenscopeaddproject
                            # Each project in the list should be added with a separate mutation
                            for project_with_access in project_dict["cicd"]["projects_with_access"]:
                                mutation = gql(
                                    """
                                    mutation cicd_projects_with_access($projectPath: ID!, $targetProjectPath: ID!) {
                                      ciJobTokenScopeAddProject(input: {projectPath: $projectPath, targetProjectPath: $targetProjectPath}) {
                                        errors
                                      }
                                    }
                                    """
                                )
                                mutation_variables = {
                                    "projectPath": project.path_with_namespace,
                                    "targetProjectPath": project_with_access
                                }
                                graphql_result = graphql_client.execute(mutation, variable_values=mutation_variables)
                                # Log result
                                logger.info("Project {project} cicd:projects_with_access GraphQL result:".format(project=project_dict["path"]))
                                logger.info(graphql_result)

                        # Save
                        project.save()
                        new_project_dict = project.asdict()
                        if old_project_dict != new_project_dict:
                            print(DeepDiff(old_project_dict, new_project_dict, exclude_regex_paths=[r"root\['permissions'\]"]).pretty())

                    logger.info("Project {project} settings:".format(project=project_dict["path"]))
                    logger.info(project)
                    logger.info("Project {project} deploy keys:".format(project=project_dict["path"]))
                    logger.info(project.keys.list(get_all=True))
                    logger.info("Project {project} deploy tokens:".format(project=project_dict["path"]))
                    logger.info(project.deploytokens.list(get_all=True))
                    logger.info("Project {project} protected branches:".format(project=project_dict["path"]))
                    logger.info(project.protectedbranches.list(get_all=True))
                    logger.info("Project {project} protected tags:".format(project=project_dict["path"]))
                    logger.info(project.protectedtags.list(get_all=True))
                    logger.info("Project {project} runners:".format(project=project_dict["path"]))
                    logger.info(project.runners.list(get_all=True))
                    # These are not available when jobs disabled
                    if not (
                        ("jobs_enabled" in project_dict and not project_dict["jobs_enabled"])
                        or
                        ("builds_access_level" in project_dict and project_dict["builds_access_level"] == "disabled")
                        or
                        ("repository_access_level" in project_dict and project_dict["repository_access_level"] == "disabled")
                    ):
                        logger.info("Project {project} environments:".format(project=project_dict["path"]))
                        logger.info(project.environments.list(get_all=True))
                        logger.info("Project {project} variables:".format(project=project_dict["path"]))
                        logger.info(project.variables.list(get_all=True))
                        for project_var in project.variables.list(get_all=True):
                            logger.info(project_var)

        if args.template_projects:

            # Connect to GitLab
            gl = gitlab.Gitlab(yaml_dict["gitlab"]["url"], private_token=GL_ADMIN_PRIVATE_TOKEN)
            gl.auth()

            # For projects
            for project_dict in yaml_dict["projects"]:

                logger.info("Found project yaml definition: {project}".format(project=project_dict))

                # Check project active
                if project_dict["active"] and "template" in project_dict:

                    # Get GitLab project for
                    project = gl.projects.get(project_dict["path"])
                    logger.info("Project {project} ssh_url_to_repo: {ssh_url_to_repo}, path_with_namespace: {path_with_namespace}".format(project=project_dict["path"], path_with_namespace=project.path_with_namespace, ssh_url_to_repo=project.ssh_url_to_repo))

                    # Reset local repo to origin or clone
                    script = textwrap.dedent(
                        """
                        if [ -d {PROJECTS_SUBDIR}/{path_with_namespace}/.git ] && ( cd {PROJECTS_SUBDIR}/{path_with_namespace}/.git && git rev-parse --is-inside-git-dir | grep -q -e true ); then
                            echo Already cloned, fetching and resetting to origin
                            cd {PROJECTS_SUBDIR}/{path_with_namespace}
                            git fetch origin
                            git reset --hard origin/master
                            git clean -ffdx
                        else
                            git clone {ssh_url_to_repo} {PROJECTS_SUBDIR}/{path_with_namespace}
                        fi
                        """
                    ).format(ssh_url_to_repo=project.ssh_url_to_repo, PROJECTS_SUBDIR=PROJECTS_SUBDIR, path_with_namespace=project.path_with_namespace)
                    logger.info("Running bash script:")
                    logger.info(script)
                    subprocess.run(script, shell=True, universal_newlines=True, check=True, executable="/bin/bash")

                    # Install templates
                    script = textwrap.dedent(
                        """
                        set -e
                        cd {template_path}
                        {cmd} ../{PROJECTS_SUBDIR}/{path_with_namespace}
                        """
                    ).format(PROJECTS_SUBDIR=PROJECTS_SUBDIR,
                        path_with_namespace=project.path_with_namespace,
                        template_path=project_dict["template"]["path"],
                        cmd=project_dict["template"]["cmd"]
                    )
                    logger.info("Running bash script:")
                    logger.info(script)
                    subprocess.run(script, shell=True, universal_newlines=True, check=True, executable="/bin/bash")

                    # Commit changes
                    script = textwrap.dedent(
                        """
                        set -e
                        cd {PROJECTS_SUBDIR}/{path_with_namespace}
                        git add -A
                        git commit -m "template installed" || true
                        {push}
                        """
                    ).format(PROJECTS_SUBDIR=PROJECTS_SUBDIR, path_with_namespace=project.path_with_namespace, push="git push" if args.git_push else "")
                    logger.info("Running bash script:")
                    logger.info(script)
                    subprocess.run(script, shell=True, universal_newlines=True, check=True, executable="/bin/bash")

        if args.bulk_delete_tags_in_projects and "projects" in yaml_dict:

            # Connect to GitLab
            gl = gitlab.Gitlab(yaml_dict["gitlab"]["url"], private_token=GL_ADMIN_PRIVATE_TOKEN)
            gl.auth()

            # For projects
            for project_dict in yaml_dict["projects"]:

                logger.info("Found project yaml definition: {project}".format(project=project_dict))

                # Check project active and 
                if project_dict["active"] and "bulk_delete_tags" in project_dict:

                    # Get GitLab project for
                    project = gl.projects.get(project_dict["path"])
                    logger.info("Project {project} ssh_url_to_repo: {ssh_url_to_repo}, path_with_namespace: {path_with_namespace}".format(project=project_dict["path"], path_with_namespace=project.path_with_namespace, ssh_url_to_repo=project.ssh_url_to_repo))

                    # Set needed project params
                    if not args.dry_run_gitlab:

                        # Loop bulk_delete_tags rules:
                        for rule in project_dict["bulk_delete_tags"]:

                            logger.info("Rule {rule}".format(rule=rule))

                            current_hour = datetime.datetime.today().hour
                            if current_hour not in rule["run_on_hours"]:
                                logger.info("Rule skipped because current hour {hour} is not in rule run_on_hours".format(hour=current_hour))
                                continue

                            # Loop over repos (subpaths) inside project
                            for repo in project.repositories.list(get_all=True):

                                # Check image_repo_regex
                                if re.search(rule["image_repo_regex"], repo.path):

                                    logger.info("Repo {repo} matched rule image_repo_regex {regex}".format(repo=repo.path, regex=rule["image_repo_regex"]))

                                    # Delete tags
                                    try:
                                        # Run bulk delete
                                        repo.tags.delete_in_bulk(
                                            name_regex_delete=rule["name_regex_delete"],
                                            name_regex_keep=rule.get("name_regex_keep", None),
                                            keep_n=rule.get("keep_n", None),
                                            older_than=rule.get("older_than", None)
                                        )
                                        logger.info("delete_in_bulk run for {path}".format(path=repo.path))
                                    # GitLab allows bulk delete only once per hour so log and ignore
                                    except gitlab.exceptions.GitlabDeleteError as e:
                                        logger.info(e)
                                    except gitlab.exceptions.GitlabHttpError as e:
                                        logger.info(e)

                    else:
                        logger.warning("--dry-run mode, skipping.")
                else:
                    logger.info("Project not active or bulk_delete_tags is emtpy. Skipping.")
        # Close connection
        if not (args.ignore_db or args.apply_variables):
            conn.close()

    # Reroute catched exception to log
    except Exception as e:
        logger.exception(e)
        logger.error("Finished {LOGO} with errors in file {file}".format(LOGO=LOGO, file=args.yaml[0] if args.yaml is not None else WORK_DIR + "/" + PROJECTS_YAML))
        sys.exit(1)

    logger.info("Finished {LOGO}".format(LOGO=LOGO))
