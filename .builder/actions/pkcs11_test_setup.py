"""
Prepare for PKCS#11 tests by configuring SoftHSM2, if it is installed.
"""

import Builder

import os
import re


class Pkcs11TestSetup(Builder.Action):

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

    def _find_softhsm_lib(self):
        """Return path to SoftHSM2 shared lib, or None if not found"""
        lib_name = 'libsofthsm2.so'
        for lib_dir in ['lib64', 'lib']:
            for base_dir in ['/usr', '/']:
                search_dir = os.path.join(base_dir, lib_dir)
                for root, dirs, files in os.walk(search_dir):
                    for name in files:
                        if name == lib_name:
                            return os.path.join(root, name)
        return None

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
        """Set up SoftHSM, and set env vars, so this machine can run the PKCS#11 tests"""

        # bail out if SoftHSM is not installed
        softhsm_lib = self._find_softhsm_lib()
        if not softhsm_lib:
            print("Skipping PKCS#11 tests: SoftHSM2 not installed")
            return

        # put SoftHSM config file and token directory under the build dir.
        softhsm2_dir = os.path.join(env.build_dir, 'softhsm2')
        env.shell.rm(softhsm2_dir, quiet=True)
        env.shell.mkdir(softhsm2_dir)

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

        # set env vars for tests
        env.shell.setenv('TEST_PKCS11_LIB', softhsm_lib)
        env.shell.setenv('TEST_PKCS11_TOKEN_LABEL', 'my-test-token')
        env.shell.setenv('TEST_PKCS11_PIN', '0000')
        env.shell.setenv('TEST_PKCS11_PKEY_LABEL', 'my-test-key')
        env.shell.setenv('TEST_PKCS11_CERT_FILE', os.path.join(resources_dir, 'unittests.crt'))
        env.shell.setenv('TEST_PKCS11_CA_FILE', os.path.join(resources_dir, 'unittests.crt'))
