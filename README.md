# gitlab-admin

## IMPORTANT!
### Gitlab version 13.12 or higher

## Setup
Env var `GL_ADMIN_PRIVATE_TOKEN` needed to access GitLab as Admin to create and setup projects.
Env vars `PG_DB_HOST`, `PG_DB_NAME`, `PG_DB_USER`, `PG_DB_PASS` for access to GitLab PostgreSQL DB are required to set these options (API lacks support):
- `skip_outdated_deployment_jobs`
- `deploy_tokens`

Add this repo as Git Submodule to a project:
```
git submodule add --name .gitlab-admin -b master -- https://github.com/microdevops-com/gitlab-admin .gitlab-admin
```

Add symlinks to submodule:
```
ln -s .gitlab-admin/requirements.txt
ln -s .gitlab-admin/issues.py
ln -s .gitlab-admin/projects.py
ln -s .gitlab-admin/settings.py
```

Install python3 requirements:
```
pip3 install -r requirements.txt
```

## `./settings.py`
Setup global GitLab settings.
Run `./settings.py --apply-settings` to apply GitLab settings.

## `./projects.py`
Setup multiple GitLab projects with settings defined by YAML, see [projects.yaml.example](projects.yaml.example) for example.

Run `./projects.py --setup-projects` to create and/or setup projects in GitLab.

Run `./projects.py --template-projects` to update templates within via git.
Git is used via local cmd run.

Run `./projects.py --bulk-delete-tags-in-projects` to bulk delete docker registry tags by rules defined in YAML.

## `./issues.py`
Import issues or epics from Jira, rules defined by YAML, see [issues.yaml.example](issues.yaml.example) for example.

Run `./issues.py --import-epics-from-jira` to import epics.
Run `./issues.py --import-issues-from-jira` to import issues.
