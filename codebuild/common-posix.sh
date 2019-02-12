#!/bin/bash

set -e

echo "Using CC=$CC CXX=$CXX"

CMAKE_ARGS="$@"
BUILD_PATH="/tmp/builds"
mkdir -p $BUILD_PATH
INSTALL_PATH="$BUILD_PATH/install"
mkdir -p $INSTALL_PATH

# install_library <git_repo> [<commit>]
function install_library {
    CURRENT_DIR=`pwd`
    cd $BUILD_PATH
    git clone https://github.com/awslabs/$1.git
    
    cd $1
    if [ -n "$2" ]; then
        git checkout $2
    fi

    cmake -DCMAKE_INSTALL_PREFIX=$INSTALL_PATH -DCMAKE_PREFIX_PATH=$INSTALL_PATH -DENABLE_SANITIZERS=ON $CMAKE_ARGS ./
    make install

    cd $CURRENT_DIR
}

# If TRAVIS_OS_NAME is OSX, skip this step (will resolve to empty string on CodeBuild)
if [ "$TRAVIS_OS_NAME" != "osx" ]; then
    sudo apt-get install libssl-dev -y
    install_library s2n 7c9069618e68214802ac7fbf45705d5f8b53135f
fi
install_library aws-c-common

if [ "$CODEBUILD_SRC_DIR" ]; then
    cd $CODEBUILD_SRC_DIR
else
    cd aws-c-io
fi

mkdir build
cd build
cmake -DCMAKE_INSTALL_PREFIX=$INSTALL_PATH -DCMAKE_PREFIX_PATH=$INSTALL_PATH -DENABLE_SANITIZERS=ON $CMAKE_ARGS ../
make

LSAN_OPTIONS=verbosity=1:log_threads=1 ctest --output-on-failure

cd ..

