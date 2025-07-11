# IMPORTANT!
- Gitlab version 13.12 or higher required.

# Setup with symlinks
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

# Setup with docker compose

Make sure your uid is set to 1000, otherwise you will have permission issues with the mounted volumes.

Check docker host docker group id, update it in `Dockerfile.compose` if needed.

Run:
```
docker compose run --rm --build gitlab-admin
```

# `./settings.py`
Setup global GitLab settings.
Run `./settings.py --apply-settings` to apply GitLab settings.

# `./projects.py`
Setup multiple GitLab projects with settings defined by YAML, see [projects.yaml.example](projects.yaml.example) for example.

Run `./projects.py --setup-projects` to create and/or setup projects in GitLab.

Run `./projects.py --template-projects` to update templates within via git.
Git is used via local cmd run.

Run `./projects.py --bulk-delete-tags-in-projects` to bulk delete docker registry tags by rules defined in YAML.

# `./issues.py`
Import issues or epics from Jira, rules defined by YAML, see [issues.yaml.example](issues.yaml.example) for example.

Run `./issues.py --import-epics-from-jira` to import epics.
Run `./issues.py --import-issues-from-jira` to import issues.

# `./registry.py`
The script is used to pull the GitLab container registry of specific project locally, then push it to another project.
This is helpful if you need to move or rename the project as GitLab does not support this while there are existing images in the registry.

Set env vars in `.env` file, docker compose will use it:
  - `PULL_GITLAB_USER` - GitLab user to pull images from registry
  - `PULL_GITLAB_TOKEN` - GitLab user token to pull images from registry and to connect to GitLab API
  - `PUSH_GITLAB_USER` - GitLab user to push images to registry
  - `PUSH_GITLAB_TOKEN` - GitLab user token to push images to registry and to connect to GitLab API

Enter docker compose container:
```
docker compose run --rm gitlab-admin
```

Pull images, you can omit `--delete-tags-after-pull` first time just to make sure everything works:
```
./registry.py --ids-file ids.txt --pull-gitlab-url https://gitlab.example.org --pull-project-path old/path
```

Pull together with deleting tags after pull, if you want to run it for the second time, backup `ids.txt` file first, as it will be cleared:
```
./registry.py --ids-file ids.txt --pull-gitlab-url https://gitlab.example.org --pull-project-path old/path --delete-tags-after-pull
```

Move or rename the project.

Check local images and note old registry location in their repository location column:
```
docker image ls
```

Push images:
```
./registry.py --ids-file ids.txt --push-gitlab-url https://gitlab.example.org --push-project-path new/path --old-registry-location gitlab.example.org:5001/old/path
```

After pushing the images second attempt will not pass, as additional tags will be added to the local images. Delete local images and pull them again to make another attempt.

Delete local images:
```
./registry.py --ids-file ids.txt --rm-images
```
