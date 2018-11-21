#!/bin/bash

set -e

CMAKE_ARGS="$@"

# install_library <git_repo> [<commit>]
function install_library {
    git clone https://github.com/awslabs/$1.git
    cd $1

    if [ -n "$2" ]; then
        git checkout $2
    fi

    mkdir build
    cd build

    cmake -DCMAKE_INSTALL_PREFIX=../../install -DENABLE_SANITIZERS=ON $CMAKE_ARGS ../
    make install

    cd ../..
}


sudo apt-get install libssl-dev

cd ../

mkdir install

install_library s2n 7c9069618e68214802ac7fbf45705d5f8b53135f
install_library aws-c-common

cd aws-c-io
mkdir build
cd build
cmake -DCMAKE_INSTALL_PREFIX=../../install -DENABLE_SANITIZERS=ON $CMAKE_ARGS ../

make

LSAN_OPTIONS=verbosity=1:log_threads=1 ctest --output-on-failure

cd ..

# ./cppcheck.sh ../install/include
