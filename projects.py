#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Import common code
from sysadmws_common import *
import gitlab
import glob
import textwrap
import subprocess
import json

# Constants and envs

LOGO="Projects"
WORK_DIR = "./"
LOG_DIR = "./log"
LOG_FILE = "projects.log"
PROJECTS_YAML = "projects.yaml"
PROJECTS_SUBDIR = ".projects"

# Main

if __name__ == "__main__":

    # Set parser and parse args
    parser = argparse.ArgumentParser(description='{LOGO} functions.'.format(LOGO=LOGO))
    parser.add_argument("--debug", dest="debug", help="enable debug", action="store_true")
    parser.add_argument("--git-push", dest="git_push", help="push after commit", action="store_true")
    parser.add_argument("--dry-run-gitlab", dest="dry_run_gitlab", help="no new objects created in gitlab", action="store_true")
    parser.add_argument("--yaml", dest="yaml", help="use file FILE instead of default projects.yaml", nargs=1, metavar=("FILE"))
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--setup-projects", dest="setup_projects", help="ensure projects created in GitLab, their settings setup", action="store_true")
    group.add_argument("--template-projects", dest="template_projects", help=" update project git repo from template using current user git creds", action="store_true")
    args = parser.parse_args()

    # Set logger and console debug
    if args.debug:
        logger = set_logger(logging.DEBUG, LOG_DIR, LOG_FILE)
    else:
        logger = set_logger(logging.ERROR, LOG_DIR, LOG_FILE)

    GL_ADMIN_PRIVATE_TOKEN = os.environ.get("GL_ADMIN_PRIVATE_TOKEN")
    if GL_ADMIN_PRIVATE_TOKEN is None:
        raise Exception("Env var GL_ADMIN_PRIVATE_TOKEN missing")

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
                        # Search groups by last name before project and match full path
                        group_name = project_dict["path"].split("/")[-2]
                        group_id = None
                        for group in gl.groups.list(search=group_name):
                            if group.full_path == group_full_path:
                                group_id = group.id
                                logger.info("Found group ID: {id}, name: {group}".format(group=group.full_name, id=group.id))
                        # Create project
                        project_name = project_dict["path"].split("/")[-1]
                        if not args.dry_run_gitlab:
                            project = gl.projects.create({'name': project_name, 'namespace_id': group_id})
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
                        project.description = project_dict["description"]
                        project.visibility = project_dict["visibility"]
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
                        # TODO: project.forward_deployment_enabled
                        # https://gitlab.com/gitlab-org/gitlab/-/issues/212621
                        # Maintainer group
                        if "maintainers_group" in project_dict:
                            # Get maintainers_group_id by maintainers_group
                            # Search groups by last name before project and match full path
                            group_name = project_dict["maintainers_group"].split("/")[-1]
                            group_id = None
                            for group in gl.groups.list(search=group_name):
                                if group.full_path == project_dict["maintainers_group"]:
                                    group_id = group.id
                                    logger.info("Found group ID: {id}, name: {group}".format(group=group.full_name, id=group.id))
                            if not any(shared_group["group_id"] == group_id for shared_group in project.shared_with_groups):
                                project.share(group_id, gitlab.MAINTAINER_ACCESS)
                        # Members
                        if "members" in project_dict:
                            for member in project_dict["members"]:
                                user_id = gl.users.list(username=member["user"])[0].id
                                logger.info("Found user ID: {id}, name: {user}".format(id=user_id, user=member["user"]))
                                try:
                                    current_member = project.members.get(user_id)
                                    current_member.access_level = member["access_level"]
                                    current_member.save()
                                except gitlab.exceptions.GitlabGetError as e:
                                    member = project.members.create({'user_id': user_id, 'access_level': member["access_level"]})
                                    member.save()
                        # Deploy keys
                        if "deploy_keys" in project_dict:
                            for deploy_key in project_dict["deploy_keys"]:
                                key = project.keys.create({'title': deploy_key["title"], 'key': deploy_key["key"]})
                        # Deploy tokens
                        if "deploy_tokens" in project_dict:
                            for deploy_token in project_dict["deploy_tokens"]:
                                # Tokens should be explicitly removed each time as revoked manually with the same name exist forever and cannot be detected revoked
                                for token in project.deploytokens.list():
                                    if token.name == deploy_token["name"]:
                                        token.delete()
                                token = project.deploytokens.create({'name': deploy_token["name"], 'scopes': deploy_token["scopes"]})
                                logger.info("Project {project} deploy token added:".format(project=project_dict["path"]))
                                logger.info(token)
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
                        # Protected branches
                        if "protected_branches" in project_dict:
                            for branch in project_dict["protected_branches"]:
                                if any(project_branch.name == branch["name"] for project_branch in project.protectedbranches.list()):
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
                                if any(project_tag.name == tag["name"] for project_tag in project.protectedtags.list()):
                                    p_tag = project.protectedtags.get(tag["name"])
                                    p_tag.delete()
                                project.protectedtags.create({'name': tag["name"], 'create_access_level': tag["create_access_level"]})
                        # MR approval rules (should be done after branch protection reset)
                        if "merge_request_approval_rules" in project_dict:
                            # Empty list before setting
                            for mrar in project.approvalrules.list():
                                if mrar.name == 'All Members':
                                    continue
                                mrar.delete()
                            for rule in project_dict["merge_request_approval_rules"]:

                                g_ids = []
                                for gr in rule["groups"]:
                                    group_name = gr.split("/")[-1]
                                    for group in gl.groups.list(search=group_name):
                                        if group.full_path == gr:
                                            g_ids.append(group.id)
                                            logger.info("Found group ID: {id}, name: {group}".format(group=group.full_name, id=group.id))

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
                        if "specific_runners_enable" in project_dict:
                            for runner_to_add in project_dict["specific_runners_enable"]:
                                for runner in gl.runners.list():
                                    if runner.description == runner_to_add:
                                        if not any(added_runner.description == runner_to_add for added_runner in project.runners.list()):
                                            project.runners.create({'runner_id': runner.id})
                        # Protected envs
                        if "protected_environments" in project_dict:
                            for env in project_dict["protected_environments"]:
                                # Create env first
                                if not any(p_env.name == env["name"] for p_env in project.environments.list()):
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
                                    curl --request POST \
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
                                subprocess.run(script, shell=True, universal_newlines=True, check=True, executable="/bin/bash")
                        # CI Variables
                        if "variables" in project_dict:
                            # We cannot update vars as key for update is not scope safe, so we delete first
                            for var in project_dict["variables"]:
                                if any(project_var.key == var["key"] for project_var in project.variables.list()):
                                    project.variables.delete(id=var["key"])
                            # Then save
                            project.save()
                            # And add again, adding is scope safe
                            for var in project_dict["variables"]:
                                var_dict = {
                                    "key": var["key"],
                                    "value": var["value"],
                                    "variable_type": var["variable_type"],
                                    "protected": var["protected"],
                                    "masked": var["masked"],
                                    "environment_scope": var["environment_scope"]
                                }
                                project.variables.create(var_dict)

                        # Save
                        project.save()
                    
                    logger.info("Project {project} settings:".format(project=project_dict["path"]))
                    logger.info(project)
                    logger.info("Project {project} deploy keys:".format(project=project_dict["path"]))
                    logger.info(project.keys.list())
                    logger.info("Project {project} deploy tokens:".format(project=project_dict["path"]))
                    logger.info(project.deploytokens.list())
                    logger.info("Project {project} protected branches:".format(project=project_dict["path"]))
                    logger.info(project.protectedbranches.list())
                    logger.info("Project {project} protected tags:".format(project=project_dict["path"]))
                    logger.info(project.protectedtags.list())
                    logger.info("Project {project} runners:".format(project=project_dict["path"]))
                    logger.info(project.runners.list())
                    logger.info("Project {project} environments:".format(project=project_dict["path"]))
                    logger.info(project.environments.list())
                    logger.info("Project {project} variables:".format(project=project_dict["path"]))
                    logger.info(project.variables.list())
                    for project_var in project.variables.list():
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

    # Reroute catched exception to log
    except Exception as e:
        logger.exception(e)
        logger.info("Finished {LOGO} with errors".format(LOGO=LOGO))
        sys.exit(1)

    logger.info("Finished {LOGO}".format(LOGO=LOGO))
