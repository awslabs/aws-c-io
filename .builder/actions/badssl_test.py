"""
Run only the TLS tests that connect to badssl, with the CA root override.
"""

import Builder
import os
from pathlib import Path


class BadsslTest(Builder.Action):

    def run(self, env):
        # Find the CA root cert relative to the source dir
        source_dir = env.project.path
        ca_root = os.path.join(source_dir, "badssl.com", "certs", "sets", "current", "gen", "crt", "ca-root.crt")

        if os.path.exists(ca_root):
            env.shell.setenv("BADSSL_CA_ROOT", ca_root)
            env.project.config['test_env']['BADSSL_CA_ROOT'] = ca_root
        else:
            print(f"WARNING: {ca_root} not found. badssl tests will use system trust store.")

        return Builder.Script([
            ['ctest', '--output-on-failure', '-R', 'tls_client_'],
        ], name='badssl-test')
