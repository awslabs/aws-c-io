"""
Prepare for PKCS#11 tests by configuring SoftHSM2, if it is installed.
"""

import Builder

import os
import re


class Pkcs11TestSetup(Builder.Action):

    def _find_softhsm_lib(self):
        """Return path to SoftHSM2 shared lib, or None if not found"""
        for lib_dir in ['lib64', 'lib']: # search lib64 before lib
            for base_dir in ['/usr/local', '/usr', '/',]:
                search_dir = os.path.join(base_dir, lib_dir)
                for root, dirs, files in os.walk(search_dir):
                    for file_name in files:
                        if 'libsofthsm2.so' in file_name:
                            return os.path.join(root, file_name)
        return None

    def _exec_softhsm2_util(self, *args, **kwargs):
        env = kwargs.pop('env')
        if not 'check' in kwargs:
            kwargs['check'] = True

        result = env.shell.exec('softhsm2-util', *args, **kwargs)

        # early versions of softhsm2-util (2.1.0 is a known offender)
        # return error code 0 and print the help if invalid args are passed.
        # This should be an error.
        #
        # invalid args can happen because later versions of softhsm2-util
        # support more args than earlier versions, so what works on your
        # machine might not work on some ancient docker image.
        if 'Usage: softhsm2-util' in result.output:
            raise Exception('softhsm2-util failed')

        return result

    def _get_token_slots(self, env):
        """Return array of IDs for slots with initialized tokens"""
        token_slot_ids = []

        output = self._exec_softhsm2_util('--show-slots', env=env, quiet=True).output

        # --- output looks like ---
        #Available slots:
        #Slot 0
        #    Slot info:
        #        ...
        #        Token present:    yes
        #    Token info:
        #        ...
        #        Initialized:      yes
        current_slot = None
        current_info_block = None
        for line in output.splitlines():
            # check for start of "Slot <ID>" block
            m = re.match(r"Slot ([0-9]+)", line)
            if m:
                current_slot = int(m.group(1))
                current_info_block = None
                continue

            if current_slot is None:
                continue

            # check for start of next indented block, like "Token info"
            m = re.match(r"    ([^ ].*)", line)
            if m:
                current_info_block = m.group(1)
                continue

            if current_info_block is None:
                continue

            # if we're in token block, check for "Initialized: yes"
            if "Token info" in current_info_block:
                if re.match(r" *Initialized: *yes", line):
                    token_slot_ids.append(current_slot)

        return token_slot_ids

    def run(self, env):
        """
        Set up this machine for running the PKCS#11 tests.
        If SoftHSM2 is not installed, the tests are skipped.
        """
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
        env.shell.setenv('SOFTHSM2_CONF', conf_path)
        with open(conf_path, 'w') as conf_file:
            conf_file.write(f"directories.tokendir = {token_dir}\n")

        # create a token
        self._exec_softhsm2_util(
            '--init-token',
            '--free', # use any free slot
            '--label', 'my-test-token',
            '--pin', '0000',
            '--so-pin', '0000',
            env=env)

        # we need to figure out which slot the new token is in because:
        # 1) old versions of softhsm2-util make you pass --slot <number>
        #    (instead of accepting --token <name> like newer versions)
        # 2) newer versions of softhsm2-util reassign new tokens to crazy
        #    slot numbers (instead of simply using 0 like older versions)
        slot = self._get_token_slots(env)[0]

        # add private key to token
        resources_dir = '../../tests/resources'
        this_dir = os.path.dirname(__file__)
        resources_dir = os.path.realpath(os.path.join(this_dir, resources_dir))
        self._exec_softhsm2_util(
            '--import', os.path.join(resources_dir, 'unittests.p8'),
            '--slot', str(slot),
            '--label', 'my-test-key',
            '--id', 'BEEFCAFE', # ID is hex
            '--pin', '0000',
            env=env)

        # for logging's sake, print the new state of things
        self._exec_softhsm2_util('--show-slots', '--pin', '0000', env=env)

        # add test env vars
        # (not that we can't just add these to current environment or they'll vanish when builder finishes this stage)
        test_env = [
            ('TEST_PKCS11_LIB', softhsm_lib),
            ('TEST_PKCS11_TOKEN_LABEL', 'my-test-token'),
            ('TEST_PKCS11_PIN', '0000'),
            ('TEST_PKCS11_PKEY_LABEL', 'my-test-key'),
            ('TEST_PKCS11_CERT_FILE', os.path.join(resources_dir, 'unittests.crt')),
            ('TEST_PKCS11_CA_FILE', os.path.join(resources_dir, 'unittests.crt')),
        ]
        for k, v in test_env:
            print(f"export {k}={v}")
            env.project.config['test_env'][k] = v






