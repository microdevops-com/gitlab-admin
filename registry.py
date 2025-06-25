#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This script is used to pull the GitLab container registry of specific project locally, then push it to another project.
# This is helpful if you need to move or rename the project as GitLab does not support this while there are existing images in the registry.

import os
import gitlab
import click
import sys
import docker

@click.command()
@click.option("--pull-gitlab-url", help="The URL of the GitLab instance to pull from.")
@click.option("--pull-project-path", help="The path of the project to pull the registry from.")
@click.option("--delete-tags-after-pull", is_flag=True, default=False, help="Delete the tags in GitLab project after pulling the image.")
@click.option("--push-gitlab-url", help="The URL of the GitLab instance to push to.")
@click.option("--push-project-path", help="The path of the project to push the registry to.")
@click.option("--old-registry-location", help="The location of the old registry, used to detect repository path inside the project registry.")
@click.option("--rm-images", is_flag=True, help="Remove local images.", default=None)
@click.option("--ids-file", help="File containing a list of image IDs pulled or to be pushed, one per line.")
def main(pull_gitlab_url, pull_project_path, push_gitlab_url, push_project_path, ids_file, delete_tags_after_pull, rm_images, old_registry_location):

    PULL_GITLAB_USER = os.environ.get("PULL_GITLAB_USER")
    if not PULL_GITLAB_USER:
        print("ERROR: environment variable PULL_GITLAB_USER is not set.")
        sys.exit(1)

    PULL_GITLAB_TOKEN = os.environ.get("PULL_GITLAB_TOKEN")
    if not PULL_GITLAB_TOKEN:
        print("ERROR: environment variable PULL_GITLAB_TOKEN is not set.")
        sys.exit(1)

    PUSH_GITLAB_USER = os.environ.get("PUSH_GITLAB_USER")
    if not PUSH_GITLAB_USER:
        print("ERROR: environment variable PUSH_GITLAB_USER is not set.")
        sys.exit(1)

    PUSH_GITLAB_TOKEN = os.environ.get("PUSH_GITLAB_TOKEN")
    if not PUSH_GITLAB_TOKEN:
        print("ERROR: environment variable PUSH_GITLAB_TOKEN is not set.")
        sys.exit(1)

    if pull_gitlab_url is None and push_gitlab_url is None and rm_images is None:
        print("ERROR: either --pull-gitlab-url or --push-gitlab-url or --rm-images must be provided.")
        sys.exit(1)

    if (
            (pull_gitlab_url is not None and (push_gitlab_url is not None or rm_images is not None))
            or (push_gitlab_url is not None and (pull_gitlab_url is not None or rm_images is not None))
            or (rm_images is not None and (pull_gitlab_url is not None or push_gitlab_url is not None))
        ):
        print("ERROR: only one of --pull-gitlab-url or --push-gitlab-url or --rm-images can be provided.")
        sys.exit(1)

    if pull_gitlab_url and pull_project_path is None:
        print("ERROR: --pull-project-path must be provided when --pull-gitlab-url is provided.")
        sys.exit(1)

    if push_gitlab_url and push_project_path is None:
        print("ERROR: --push-project-path must be provided when --push-gitlab-url is provided.")
        sys.exit(1)
    
    if push_gitlab_url and old_registry_location is None:
        print("ERROR: --old-registry-location must be provided when --push-gitlab-url is provided.")
        sys.exit(1)
    
    if ids_file is None:
        print("ERROR: --ids-file must be provided.")
        sys.exit(1)
    
    if pull_project_path:

        gl = gitlab.Gitlab(pull_gitlab_url, private_token=PULL_GITLAB_TOKEN)
        gl.auth()

        docker_client = docker.from_env()

        project = gl.projects.get(pull_project_path)

        docker_client.login(
            username=PULL_GITLAB_USER,
            password=PULL_GITLAB_TOKEN,
            registry=project.container_registry_image_prefix.split('/')[0]
        )

        with open(ids_file, 'w') as file:

            for repository in project.repositories.list(all=True, tags_count=True):

                print(f"Pulling repository '{repository.id}' from project '{project.path_with_namespace}', path: {repository.path}, tags_count: {repository.tags_count}.")
                for tag in repository.tags.list(all=True):

                    tag_extended = repository.tags.get(tag.name)
                    print(f"  Pulling tag '{tag_extended.name}', location: {tag_extended.location}, created_at: {tag_extended.created_at}, total_size: {tag_extended.total_size}.")

                    pull_image = docker_client.images.pull(tag_extended.location)
                    print(f"  Pulled image: {pull_image.id}.")

                    # Remove something:image_id before writing into the file
                    if ':' in pull_image.id:
                        pull_image_id = pull_image.id.split(':')[1]

                    file.write(f"{pull_image_id}\n")

                    if delete_tags_after_pull:
                        print(f"  Deleting tag '{tag_extended.name}' from project '{project.path_with_namespace}'.")
                        tag_extended.delete()

        docker_client.close()

    if push_project_path:

        gl = gitlab.Gitlab(push_gitlab_url, private_token=PUSH_GITLAB_TOKEN)
        gl.auth()

        docker_client = docker.from_env()

        project = gl.projects.get(push_project_path)

        docker_client.login(
            username=PUSH_GITLAB_USER,
            password=PUSH_GITLAB_TOKEN,
            registry=project.container_registry_image_prefix.split('/')[0]
        )

        with open(ids_file, 'r') as file:

            for line in file:
                image_id = line.strip()

                image = docker_client.images.get(image_id)
                print(f"Pushing image: {image.id}.")

                # If the image tag contains two colons, it means it has a port specified.
                if ':' in image.tags[0] and image.tags[0].count(':') > 1:
                    image_tag = image.tags[0].split(':')[2]
                    image_without_tag = image.tags[0].split(':')[0] + ":" + image.tags[0].split(':')[1]
                # If the image tag contains one colon, it means the port is not specified, and the tag is after the first colon.
                elif ':' in image.tags[0] and image.tags[0].count(':') == 1:
                    image_tag = image.tags[0].split(':')[1]
                    image_without_tag = image.tags[0].split(':')[0]
                # In other cases just use skip this image.
                else:
                    print(f"  Image {image.id} has no repository specific tag, skipping.")
                    continue

                print(f"  Image {image.id} has repository specific tag: {image.tags[0]} and tag: {image_tag}.")

                # Remove old_registry_location from the image_without_tag - it will give repository path inside project registry.
                repository_path = image_without_tag.replace(old_registry_location, '')

                # Add a tag to the image for the new repository in the new project.
                new_tag = f"{project.container_registry_image_prefix}{repository_path}:{image_tag}"
                print(f"  Tagging image {image.id} with new repository specific tag: {new_tag}.")
                image.tag(new_tag)

                # Push the image to the new project.
                print(f"  Pushing image {image.id} to new project {project.path_with_namespace} with tag: {new_tag}.")
                push_image = docker_client.images.push(new_tag)

        docker_client.close()

    if rm_images:

        docker_client = docker.from_env()

        with open(ids_file, 'r') as file:

            for line in file:
                image_id = line.strip()
                print(f"Removing image: {image_id}.")
                docker_client.images.remove(image=image_id, force=True)

        docker_client.close()

if __name__ == "__main__":
    main()
