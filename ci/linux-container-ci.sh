#!/bin/bash
# $1 - Package Name
# $2 - Builder version
# $3 - Ecr Repo
# $4 - Image Name

set -e

PACKAGE_NAME=$1
shift
BUILDER_VERSION=$1
shift
ECR_REPO=$1
shift
IMAGE_NAME=$1
shift

aws ecr get-login-password | docker login ${ECR_REPO} -u AWS --password-stdin
export DOCKER_IMAGE=${ECR_REPO}/${IMAGE_NAME}:${BUILDER_VERSION}
docker pull $DOCKER_IMAGE
docker run --env GITHUB_REF $DOCKER_IMAGE --version=${BUILDER_VERSION} build -p ${PACKAGE_NAME} "$@"
