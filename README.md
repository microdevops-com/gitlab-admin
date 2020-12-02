# gitlab-admin

## Setup
Env var `GL_ADMIN_PRIVATE_TOKEN` needed to access GitLab as Admin to create and setup projects.
Env vars `PG_DB_HOST`, `PG_DB_NAME`, `PG_DB_USER`, `PG_DB_PASS` for access to GitLab PostgreSQL DB are required to set these options (API lacks support):
- `skip_outdated_deployment_jobs`
- `deploy_tokens`

Add this repo as Git Submodule to a project:
```
git submodule add --name .gitlab-admin -b master -- https://github.com/sysadmws/gitlab-admin .gitlab-admin
```

Install python3 requirements:
```
pip3 install -r requirements.txt
```

## `./settings.py`
Setup global GitLab settings.

## `./projects.py`
Setup multiple GitLab projects with settings defined by YAML, see [projects.yaml.example](projects.yaml.example) for example.

Run `./projects.py --setup-projects` to create and/or setup projects in GitLab.

Run `./projects.py --template-projects` to update templates within via git.
Git is used via local cmd run.

Run `./projects.py --bulk-delete-tags-in-projects` to bulk delete docker registry tags by rules defined in YAML.
