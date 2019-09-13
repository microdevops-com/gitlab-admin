# gitlab-projects
Setup multiple GitLab projects with settings defined by YAML, see [projects.yaml.example](projects.yaml.example) for example.
Run `./projects.py -setup-projects` to create and/or setup projects in GitLab.
Run `./projects.py --template-projects` to update templates within via git.
Env var `GL_ADMIN_PRIVATE_TOKEN` needed to access GitLab as Admin to create and setup projects.
Git is used via local cmd run.
