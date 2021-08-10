"""
Prepare for PKCS#11 tests.
Assumes SoftHSM2 is installed.
"""

import Builder

import os
import re


class Pkcs11TestSetup(Builder.Action):

    def _find_softhsm_lib(self):
        """Return path to SoftHSM2 lib, or None if not found"""
        base_dirs = ['/usr', '/']
        lib_dirs = ['lib64', 'lib']
        lib_name = 'libsofthsm2.so'
        for base_dir in base_dirs:
            for lib_dir in lib_dirs:
                search_dir = os.path.join(base_dir, lib_dir)
                for root, dirs, files in os.walk(search_dir):
                    for name in files:
                        if name == lib_name:
                            return os.path.join(root, name)
        return None

    def _count_tokens(self, env):
        """Return number of slots with initialized tokens"""
        output = env.shell.exec('softhsm2-util', '--show-slots', quiet=True, check=True).output
        count = 0
        for line in output.splitlines():
            if re.match(r" *Initialized: *yes", line):
                count += 1
        return count

    def run(self, env):
        """Set up SoftHSM, and set env vars, so this machine can run the PKCS#11 tests"""
        # bail out if SoftHSM is not installed
        softhsm_lib = self._find_softhsm_lib()
        if not softhsm_lib:
            print("Skipping PKCS#11 tests: SoftHSM2 not installed")
            return

        # bail out if SoftHSM already has tokens installed
        # that means we're probably on a user machine,
        # and we don't want to mess with their existing configuration
        if self._count_tokens(env) > 0:
            print("Skipping PKCS#11 test setup: SoftHSM2 tokens already exist on this machine")
            return

        # create a token
        env.shell.exec('softhsm2-util',
                       '--init-token',
                       '--free', # use any free slot
                       '--token', 'my-test-token',
                       '--pin', '0000',
                       '--so-pin', '0000',
                       check=True)

        # add private key to token
        resources_dir = os.path.realpath(os.path.join(__file__, '..', '..', 'tests', 'resources'))
        pkey_path = os.path.join(resources_dir, 'unittests.p8')
        env.shell.exec('softhsm2-util',
                       '--import', pkey_path,
                       '--token', 'my-test-token',
                       '--label', 'my-test-key',
                       '--id', 'BEEFCAFE', # ID is hex
                       '--pin', '0000',
                       check = True)

        # set env vars for tests
        env.shell.setenv('TEST_PKCS11_LIB', softhsm_lib)
        env.shell.setenv('TEST_PKCS11_TOKEN_LABEL', 'my-test-token')
        env.shell.setenv('TEST_PKCS11_PKEY_LABEL', 'my-test-key')
        env.shell.setenv('TEST_PKCS11_CERT_FILE', os.path.join(resources_dir, 'unittests.crt'))
        env.shell.setenv('TEST_PKCS11_CA_FILE', os.path.join(resources_dir, 'unittests.crt'))
