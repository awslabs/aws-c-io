#!/bin/bash
# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at
#
#  http://aws.amazon.com/apache2.0
#
# or in the "license" file accompanying this file. This file is distributed
# on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.
#
set -e

PROJECT_DIR=`pwd`
cd ..

#build aws-c-common
git clone https://github.com/awslabs/aws-c-common.git
mkdir local-install
mkdir common-build && cd common-build
cmake -DCMAKE_INSTALL_PREFIX="../local-install" ../aws-c-common
make install
cd ..

#build aws-c-io
cd $PROJECT_DIR
mkdir io-build && cd io-build
cmake -DCMAKE_INSTALL_PREFIX="../../local-install" $PROJECT_DIR
make && make test

