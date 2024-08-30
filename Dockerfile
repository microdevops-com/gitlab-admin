FROM python:3.10


###
### Upgrade (install ps)
###
RUN set -eux \
    && DEBIAN_FRONTEND=noninteractive apt update -qq \
    && DEBIAN_FRONTEND=noninteractive apt install -qq -y --no-install-recommends --no-install-suggests \
        procps curl bash\
    && apt autoclean \
    && apt clean \
    && true

###
### Envs
###
ENV MY_USER="app" \
    MY_GROUP="app"

ARG DOCKER_UID=1000
ARG DOCKER_GID=1000

###
### User/Group
###
RUN set -eux \
	&& groupadd -g ${DOCKER_GID} -r ${MY_GROUP} \
	&& useradd -d /home/${MY_USER} -u ${DOCKER_UID} -m -s /bin/bash -g ${MY_GROUP} ${MY_USER} \
    && true



RUN set -eux \
    && DEBIAN_FRONTEND=noninteractive apt install -qq -y libpq-dev build-essential \
    && true

COPY requirements.txt /requirements.txt

RUN pip install -r /requirements.txt

COPY . /app

WORKDIR /app/data

