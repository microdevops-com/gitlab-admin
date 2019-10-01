#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Import common code
from sysadmws_common import *
import gitlab
import glob
import textwrap
import subprocess

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

        # Read PROJECTS_YAML
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
                        logger.info("Salt project {project}, creating".format(project=project_dict["path"]))
                        # Search for the group
                        # Split and join up to last slash project path
                        group_full_path = "/".join(project_dict["path"].split("/")[:-1])
                        # Search groups by last name before project and match full path
                        group_name = project_dict["path"].split("/")[-2]
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
                        # Maintainer group
                        if "maintainers_group" in project_dict:
                            # Get maintainers_group_id by maintainers_group
                            # Search groups by last name before project and match full path
                            group_name = project_dict["maintainers_group"].split("/")[-1]
                            for group in gl.groups.list(search=group_name):
                                if group.full_path == project_dict["maintainers_group"]:
                                    group_id = group.id
                                    logger.info("Found group ID: {id}, name: {group}".format(group=group.full_name, id=group.id))
                            if not any(shared_group["group_id"] == group_id for shared_group in project.shared_with_groups):
                                project.share(group_id, gitlab.MAINTAINER_ACCESS)
                        # Deploy keys
                        if "deploy_keys" in project_dict:
                            for deploy_key in project_dict["deploy_keys"]:
                                key = project.keys.create({'title': deploy_key["title"], 'key': deploy_key["key"]})
                        # Protected tags
                        if "protected_tags" in project_dict:
                            for tag in project_dict["protected_tags"]:
                                if not any(project_tag.name == tag for project_tag in project.protectedtags.list()):
                                    project.protectedtags.create({'name': tag, 'create_access_level': '40'})
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
                    logger.info("Project {project} protected tags:".format(project=project_dict["path"]))
                    logger.info(project.protectedtags.list())
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
