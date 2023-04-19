"""
Prepare for PKCS#11 tests by configuring SoftHSM2, if it is installed.
"""

import Builder

import os
import re


class Pkcs11TestSetup(Builder.Action):
    """
    Set up this machine for running the PKCS#11 tests.
    If SoftHSM2 cannot be installed, the tests are skipped.

    This action should be run in the 'pre_build_steps' or 'build_steps' stage.
    """

    def run(self, env):
        if not env.project.needs_tests(env):
            print("Skipping PKCS#11 setup because tests disabled for project")
            return

        self.env = env

        # total hack: don't run PKCS#11 tests when building all C libs with -DBUILD_SHARED_LIBS=ON.
        # here's what happens:  libsofthsm2.so loads the system libcrypto.so and
        # s2n loads the aws-lc's libcrypto.so and really strange things start happening.
        # this wouldn't happen in the real world, just in our tests, so just bail out
        if hasattr(env.args, "cmake_extra"):
            if any('BUILD_SHARED_LIBS=ON' in arg for arg in env.args.cmake_extra):
                print(
                    "WARNING: PKCS#11 tests disabled when BUILD_SHARED_LIBS=ON due to weird libcrypto.so behavior")
                return

        # try to install softhsm
        try:
            softhsm_install_acion = Builder.InstallPackages(['softhsm'])
            softhsm_install_acion.run(env)
        except:
            print("WARNING: softhsm could not be installed. PKCS#11 tests are disabled")
            return

        softhsm_lib = self._find_softhsm_lib()
        if softhsm_lib is None:
            print("WARNING: libsofthsm2.so not found. PKCS#11 tests are disabled")
            return

        # set cmake flag so PKCS#11 tests are enabled
        env.project.config['cmake_args'].append('-DENABLE_PKCS11_TESTS=ON')

        # put SoftHSM config file and token directory under the build dir.
        softhsm2_dir = os.path.join(env.build_dir, 'softhsm2')
        conf_path = os.path.join(softhsm2_dir, 'softhsm2.conf')
        token_dir = os.path.join(softhsm2_dir, 'tokens')
        env.shell.mkdir(token_dir)
        self._setenv('SOFTHSM2_CONF', conf_path)
        with open(conf_path, 'w') as conf_file:
            conf_file.write(f"directories.tokendir = {token_dir}\n")

        # print SoftHSM version
        self._exec_softhsm2_util('--version')

        # sanity check SoftHSM is working
        self._exec_softhsm2_util('--show-slots')

        # set env vars for tests
        self._setenv('TEST_PKCS11_LIB', softhsm_lib)
        self._setenv('TEST_PKCS11_TOKEN_DIR', token_dir)

    def _find_softhsm_lib(self):
        """Return path to SoftHSM2 shared lib, or None if not found"""

        # note: not using `ldconfig --print-cache` to find it because
        # some installers put it in weird places where ldconfig doesn't look
        # (like in a subfolder under lib/)

        for lib_dir in ['lib64', 'lib']:  # search lib64 before lib
            for base_dir in ['/usr/local', '/usr', '/', ]:
                search_dir = os.path.join(base_dir, lib_dir)
                for root, dirs, files in os.walk(search_dir):
                    for file_name in files:
                        if 'libsofthsm2.so' in file_name:
                            return os.path.join(root, file_name)
        return None

    def _exec_softhsm2_util(self, *args, **kwargs):
        if not 'check' in kwargs:
            kwargs['check'] = True

        result = self.env.shell.exec('softhsm2-util', *args, **kwargs)

        # older versions of softhsm2-util (2.1.0 is a known offender)
        # return error code 0 and print the help if invalid args are passed.
        # This should be an error.
        #
        # invalid args can happen because newer versions of softhsm2-util
        # support more args than older versions, so what works on your
        # machine might not work on some ancient docker image.
        if 'Usage: softhsm2-util' in result.output:
            raise Exception('softhsm2-util failed')

        return result

    def _setenv(self, var, value):
        """
        Set environment variable now,
        and ensure the environment variable is set again when tests run
        """
        self.env.shell.setenv(var, value)
        self.env.project.config['test_env'][var] = value
