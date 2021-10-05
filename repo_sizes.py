#!/usr/bin/env python3
# coding: utf-8

# credits: https://pastebin.com/AdhDJKh5

import os
from os.path import join, getsize
import subprocess

def get_human_readable_size(size,precision=2):
    suffixes=['B','KB','MB','GB','TB']
    suffixIndex = 0
    while size > 1024 and suffixIndex < 4:
        suffixIndex += 1
        size = size/1024.0
    return "%.*f%s"%(precision,size,suffixes[suffixIndex])


def scan(dir):
    if (os.path.isdir("{}/_layers".format(dir))):
        layers = os.listdir("{}/_layers/sha256".format(dir))
        imagesize = 0
        # get image size
        for layer in layers:
            # get size of layer
            for root, dirs, files in os.walk("{}/blobs/sha256/{}/{}".format(registry_path, layer[:2], layer)):
                imagesize += (sum(getsize(join(root, name)) for name in files))
        repos.append({'dir': dir, 'size': imagesize})

    for subdir in os.listdir(dir):
        if (os.path.isdir("{}/{}".format(dir, subdir))):
            scan("{}/{}".format(dir, subdir))

registry_path = '/var/lib/gitlab_docker_registry/docker/registry/v2'
repos = []

for dir in os.listdir("{}/repositories".format(registry_path)):
    scan("{}/repositories/{}".format(registry_path, dir))

repos.sort(key=lambda k: k['size'], reverse=True)
for repo in repos:
    print("{}: {}".format(repo['dir'], get_human_readable_size(repo['size'])))
