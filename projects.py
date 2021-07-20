#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Import common code
from sysadmws_common import *

import gitlab
import glob
import textwrap
import subprocess
import json
import re
import psycopg2
import datetime
import requests

# Constants and envs

LOGO="Projects"
WORK_DIR = "./"
LOG_DIR = "./log"
LOG_FILE = "projects.log"
PROJECTS_YAML = "projects.yaml"
PROJECTS_SUBDIR = ".projects"

# Custom Exceptions
class SubprocessRunError(Exception):
    pass

# Main

if __name__ == "__main__":

    # Set parser and parse args
    parser = argparse.ArgumentParser(description='{LOGO} functions.'.format(LOGO=LOGO))
    parser.add_argument("--debug", dest="debug", help="enable debug", action="store_true")
    parser.add_argument("--git-push", dest="git_push", help="push after commit", action="store_true")
    parser.add_argument("--dry-run-gitlab", dest="dry_run_gitlab", help="no new objects created in gitlab", action="store_true")
    parser.add_argument("--yaml", dest="yaml", help="use file FILE instead of default projects.yaml", nargs=1, metavar=("FILE"))
    parser.add_argument("--ignore-db", dest="ignore_db", help="ignore connect to db if do not use specific options", action="store_true")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--setup-projects", dest="setup_projects", help="ensure projects created in GitLab, their settings setup", action="store_true")
    group.add_argument("--template-projects", dest="template_projects", help="update projects git repos from template using current user git creds", action="store_true")
    group.add_argument("--bulk-delete-tags-in-projects", dest="bulk_delete_tags_in_projects", help="bulk delete tags in projects", action="store_true")
    args = parser.parse_args()

    # Set logger and console debug
    if args.debug:
        logger = set_logger(logging.DEBUG, LOG_DIR, LOG_FILE)
    else:
        logger = set_logger(logging.ERROR, LOG_DIR, LOG_FILE)

    GL_ADMIN_PRIVATE_TOKEN = os.environ.get("GL_ADMIN_PRIVATE_TOKEN")

    if not args.ignore_db:
        if GL_ADMIN_PRIVATE_TOKEN is None:
            raise Exception("Env var GL_ADMIN_PRIVATE_TOKEN missing")

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
            projects_yaml_dict = load_yaml("{0}".format(args.yaml[0]), logger)
            if projects_yaml_dict is None:
                raise Exception("Config file error or missing: {0}".format(args.yaml[0]))
        else:
            projects_yaml_dict = load_yaml("{0}/{1}".format(WORK_DIR, PROJECTS_YAML), logger)
            if projects_yaml_dict is None:
                raise Exception("Config file error or missing: {0}/{1}".format(WORK_DIR, PROJECTS_YAML))
        
        # Connect to PG
        if not args.ignore_db:
            dsn = "host={} dbname={} user={} password={}".format(PG_DB_HOST, PG_DB_NAME, PG_DB_USER, PG_DB_PASS)
            conn = psycopg2.connect(dsn)

        # Do tasks

        if args.setup_projects:
            
            # Connect to GitLab
            gl = gitlab.Gitlab(projects_yaml_dict["gitlab"]["url"], private_token=GL_ADMIN_PRIVATE_TOKEN)
            gl.auth()

            # For projects
            for project_dict in projects_yaml_dict["projects"]:

                logger.info("Found project yaml definition: {project}".format(project=project_dict))

                # Check project active
                if project_dict["active"]:
            
                    # Get GitLab project
                    try:
                        logger.info("Checking project {project}".format(project=project_dict["path"]))
                        project = gl.projects.get(project_dict["path"])
                    except gitlab.exceptions.GitlabGetError as e:
                        # Create if not found
                        logger.info("Project {project}, creating".format(project=project_dict["path"]))
                        # Search for the group
                        # Split and join up to last slash project path
                        group_full_path = "/".join(project_dict["path"].split("/")[:-1])
                        project_path = project_dict["path"].split("/")[-1]
                        # Search groups by last name before project and match full path
                        group_name = project_dict["path"].split("/")[-2]
                        group = gl.groups.get(group_full_path)
                        group_id = group.id
                        logger.info("Found group ID: {id}, name: {group}".format(group=group.full_name, id=group.id))
                        # Create project
                        if not args.dry_run_gitlab:
                            project = gl.projects.create({'name': project_dict["name"], 'namespace_id': group_id, 'path': project_path})
                            # Add first files on creating
                            f = project.files.create(
                                {
                                    'file_path': 'README.md',
                                    'branch': 'master',
                                    'content': project_dict["description"],
                                    'author_email': projects_yaml_dict["gitlab"]["author_email"],
                                    'author_name': projects_yaml_dict["gitlab"]["author_name"],
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
                                        gl_member = project.members.create({'user_id': user_id, 'access_level': member["access_level"]})
                                        gl_member.save()
                                if "group" in member:
                                    group_id = gl.groups.get(member["group"]).id
                                    if not any(shared_group["group_id"] == group_id for shared_group in project.shared_with_groups):
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
                                    f'{projects_yaml_dict["gitlab"]["url"]}/api/v4/projects/{project_id}/deploy_tokens?active=true',
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
                                        f'{projects_yaml_dict["gitlab"]["url"]}/api/v4/projects/{project_id}/deploy_tokens/',
                                        headers={'PRIVATE-TOKEN': GL_ADMIN_PRIVATE_TOKEN},
                                        json=data
                                    )

                                    response = response.json()
                                    logger.info("Project {project} deploy token added:".format(project=project_dict["path"]))
                                    logger.info(f"\n-------------------------\nToken: {response['token']}\n-------------------------")

                        # MR approval rules
                        if "approvals_before_merge" in project_dict:
                            p_mras = project.approvals.get()
                            p_mras.approvals_before_merge = project_dict["approvals_before_merge"]
                            p_mras.save()
                        if "reset_approvals_on_push" in project_dict:
                            p_mras = project.approvals.get()
                            p_mras.reset_approvals_on_push = project_dict["reset_approvals_on_push"]
                            p_mras.save()
                        if "disable_overriding_approvers_per_merge_request" in project_dict:
                            p_mras = project.approvals.get()
                            p_mras.disable_overriding_approvers_per_merge_request = project_dict["disable_overriding_approvers_per_merge_request"]
                            p_mras.save()
                        if "merge_requests_author_approval" in project_dict:
                            p_mras = project.approvals.get()
                            p_mras.merge_requests_author_approval = project_dict["merge_requests_author_approval"]
                            p_mras.save()
                        if "merge_requests_disable_committers_approval" in project_dict:
                            p_mras = project.approvals.get()
                            p_mras.merge_requests_disable_committers_approval = project_dict["merge_requests_disable_committers_approval"]
                            p_mras.save()
                        if "require_password_to_approve" in project_dict:
                            p_mras = project.approvals.get()
                            p_mras.require_password_to_approve = project_dict["require_password_to_approve"]
                            p_mras.save()
                        
                        # Skip outdated deployment jobs
                        if "skip_outdated_deployment_jobs" in project_dict:
                            project_id = project.id
                            data = {
                                'ci_forward_deployment_enabled': project_dict["skip_outdated_deployment_jobs"]
                            }
                            response = requests.put(
                                f'{projects_yaml_dict["gitlab"]["url"]}/api/v4/projects/{project_id}',
                                headers={'PRIVATE-TOKEN': GL_ADMIN_PRIVATE_TOKEN},
                                json=data
                            )

                            logger.info(f'Project skip_outdated_deployment_jobs set via api to {project_dict["skip_outdated_deployment_jobs"]}')
                        
                        # Squash settings
                        if "squash_commits_when_merging" in project_dict:
                            if project_dict["squash_commits_when_merging"] == "do_not_allow":
                                squash_option = 0
                            if project_dict["squash_commits_when_merging"] == "allow":
                                squash_option = 3
                            if project_dict["squash_commits_when_merging"] == "encourage":
                                squash_option = 2
                            if project_dict["squash_commits_when_merging"] == "require":
                                squash_option = 1
                            # This also lacks api support
                            cur = conn.cursor()
                            sql = "UPDATE project_settings SET squash_option={squash_option} WHERE project_id = {id}".format(squash_option=squash_option, id=project.id)
                            try:
                                cur.execute(sql)
                                logger.info("Query execution status:")
                                logger.info(cur.statusmessage)
                                conn.commit()
                            except Exception as e:
                                raise Exception("Caught exception on query execution")
                            cur.close()
                            logger.info("Project squash_commits_when_merging set via db to {squash_option}".format(squash_option=project_dict["squash_commits_when_merging"]))

                        # Protected branches
                        if "protected_branches" in project_dict:
                            for branch in project_dict["protected_branches"]:
                                if any(project_branch.name == branch["name"] for project_branch in project.protectedbranches.list(all=True)):
                                    p_branch = project.protectedbranches.get(branch["name"])
                                    p_branch.delete()
                                project.protectedbranches.create(
                                    {
                                        'name': branch["name"],
                                        'push_access_level': branch["push_access_level"],
                                        'merge_access_level': branch["merge_access_level"],
                                        'merge_access_level': branch["merge_access_level"],
                                        'code_owner_approval_required': branch["code_owner_approval_required"]
                                    }
                                )
                            project.save()
                        # Protected tags
                        if "protected_tags" in project_dict:
                            for tag in project_dict["protected_tags"]:
                                if any(project_tag.name == tag["name"] for project_tag in project.protectedtags.list(all=True)):
                                    p_tag = project.protectedtags.get(tag["name"])
                                    p_tag.delete()
                                project.protectedtags.create({'name': tag["name"], 'create_access_level': tag["create_access_level"]})
                        # MR approval rules (should be done after branch protection reset)
                        if "merge_request_approval_rules" in project_dict:
                            # Empty list before setting
                            for mrar in project.approvalrules.list(all=True):
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
                                for runner in gl.runners.list(all=True):
                                    if runner.description == runner_to_add:
                                        if not any(added_runner.description == runner_to_add for added_runner in project.runners.list(all=True)):
                                            project.runners.create({'runner_id': runner.id})

                        # Protected envs
                        if "protected_environments" in project_dict:
                            for env in project_dict["protected_environments"]:
                                # Create env first
                                if not any(p_env.name == env["name"] for p_env in project.environments.list(all=True)):
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
                                    gitlab_url=projects_yaml_dict["gitlab"]["url"],
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
                        if "variables" in project_dict:
                            # Expand quick key_values sets
                            project_dict_variables = []
                            for var in project_dict["variables"]:
                                if "key_values" in var:
                                    for k, v in var["key_values"].items():
                                        project_dict_variables.append(
                                            {
                                                "variable_type": var["variable_type"],
                                                "protected": var["protected"],
                                                "masked": var["masked"],
                                                "environment_scope": var["environment_scope"],
                                                "key": k,
                                                "value": v
                                            }
                                        )
                                else:
                                    project_dict_variables.append(var)
                            # Check variables_clean_all_before_set
                            if "variables_clean_all_before_set" in project_dict and project_dict["variables_clean_all_before_set"]:
                                for project_var in project.variables.list(all=True):
                                    # There is a bug (at least at python-gitlab 2.5.0):
                                    # gitlab.exceptions.GitlabDeleteError: 409: There are multiple variables with provided parameters. Please use 'filter[environment_scope]'
                                    # So delete via direct curl API call
                                    script = textwrap.dedent(
                                        """
                                        curl --request DELETE \
                                                --header "PRIVATE-TOKEN: {private_token}" \
                                                "{gitlab_url}/api/v4/projects/{path_with_namespace_encoded}/variables/{key}?filter%5Benvironment_scope%5D={environment_scope}"
                                        """
                                    ).format(
                                        gitlab_url=projects_yaml_dict["gitlab"]["url"],
                                        private_token=GL_ADMIN_PRIVATE_TOKEN,
                                        path_with_namespace_encoded=project.path_with_namespace.replace("/", "%2F"),
                                        key=project_var.key,
                                        environment_scope=project_var.environment_scope.replace("*", "%2A")
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
                                    logger.info("Deleting var {scope} / {var} because of variables_clean_all_before_set".format(scope=project_var.environment_scope, var=project_var.key))
                            else:
                                # We cannot update vars as key for update is not scope safe, so we delete first if var state is not as needed
                                for var in project_dict_variables:
                                    for project_var in project.variables.list(all=True):
                                        if project_var.environment_scope == var["environment_scope"] and project_var.key == var["key"]:
                                            if (
                                                project_var.value != str(var["value"])
                                                or
                                                project_var.variable_type != var["variable_type"] 
                                                or
                                                project_var.protected != var["protected"]
                                                or
                                                project_var.masked != var["masked"]
                                                ):
                                                # project_var.delete()
                                                # There is a bug (at least at python-gitlab 2.5.0):
                                                # gitlab.exceptions.GitlabDeleteError: 409: There are multiple variables with provided parameters. Please use 'filter[environment_scope]'
                                                # So delete via direct curl API call
                                                script = textwrap.dedent(
                                                    """
                                                    curl --request DELETE \
                                                            --header "PRIVATE-TOKEN: {private_token}" \
                                                            "{gitlab_url}/api/v4/projects/{path_with_namespace_encoded}/variables/{key}?filter%5Benvironment_scope%5D={environment_scope}"
                                                    """
                                                ).format(
                                                    gitlab_url=projects_yaml_dict["gitlab"]["url"],
                                                    private_token=GL_ADMIN_PRIVATE_TOKEN,
                                                    path_with_namespace_encoded=project.path_with_namespace.replace("/", "%2F"),
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
                            # Then save
                            project.save()
                            # And add again, adding is scope safe
                            for var in project_dict_variables:
                                if not any(project_var.environment_scope == var["environment_scope"] and project_var.key == var["key"] for project_var in project.variables.list(all=True)):
                                    var_dict = {
                                        "key": var["key"],
                                        "value": var["value"],
                                        "variable_type": var["variable_type"],
                                        "protected": var["protected"],
                                        "masked": var["masked"],
                                        "environment_scope": var["environment_scope"]
                                    }
                                    project.variables.create(var_dict)
                                    logger.info("Var {scope} / {var} created".format(scope=var["environment_scope"], var=var["key"]))

                        # Push Rules
                        if "push_rules" in project_dict:

                            # Get existing rules, None if not exist
                            pr = project.pushrules.get()
                            if pr is None:
                                # At least one option is required to create, use commit_committer_check
                                project.pushrules.create({'commit_committer_check': project_dict["push_rules"]["commit_committer_check"]})
                                pr = project.pushrules.get()

                            # Set othe params
                            pr.commit_committer_check = project_dict["push_rules"]["commit_committer_check"]
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

                        # Save
                        project.save()
                    
                    logger.info("Project {project} settings:".format(project=project_dict["path"]))
                    logger.info(project)
                    logger.info("Project {project} deploy keys:".format(project=project_dict["path"]))
                    logger.info(project.keys.list(all=True))
                    logger.info("Project {project} deploy tokens:".format(project=project_dict["path"]))
                    logger.info(project.deploytokens.list(all=True))
                    logger.info("Project {project} protected branches:".format(project=project_dict["path"]))
                    logger.info(project.protectedbranches.list(all=True))
                    logger.info("Project {project} protected tags:".format(project=project_dict["path"]))
                    logger.info(project.protectedtags.list(all=True))
                    logger.info("Project {project} runners:".format(project=project_dict["path"]))
                    logger.info(project.runners.list(all=True))
                    # These are not available when jobs disabled
                    if not (
                        ("jobs_enabled" in project_dict and not project_dict["jobs_enabled"])
                        or
                        ("builds_access_level" in project_dict and project_dict["builds_access_level"] == "disabled")
                        or
                        ("repository_access_level" in project_dict and project_dict["repository_access_level"] == "disabled")
                    ):
                        logger.info("Project {project} environments:".format(project=project_dict["path"]))
                        logger.info(project.environments.list(all=True))
                        logger.info("Project {project} variables:".format(project=project_dict["path"]))
                        logger.info(project.variables.list(all=True))
                        for project_var in project.variables.list(all=True):
                            logger.info(project_var)
            
        if args.template_projects:
            
            # Connect to GitLab
            gl = gitlab.Gitlab(projects_yaml_dict["gitlab"]["url"], private_token=GL_ADMIN_PRIVATE_TOKEN)
            gl.auth()

            # For projects
            for project_dict in projects_yaml_dict["projects"]:

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

        if args.bulk_delete_tags_in_projects:
            
            # Connect to GitLab
            gl = gitlab.Gitlab(projects_yaml_dict["gitlab"]["url"], private_token=GL_ADMIN_PRIVATE_TOKEN)
            gl.auth()

            # For projects
            for project_dict in projects_yaml_dict["projects"]:

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
                            for repo in project.repositories.list(all=True):

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
                                        logger.exception(e)

        # Close connection
        if not args.ignore_db:
            conn.close()

    # Reroute catched exception to log
    except Exception as e:
        logger.exception(e)
        logger.error("Finished {LOGO} with errors in file {file}".format(LOGO=LOGO, file=args.yaml[0] if args.yaml is not None else WORK_DIR + "/" + PROJECTS_YAML))
        sys.exit(1)

    logger.info("Finished {LOGO}".format(LOGO=LOGO))
