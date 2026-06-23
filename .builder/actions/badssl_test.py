"""
Run only the TLS tests that connect to badssl.
"""

import Builder
import os


class BadsslTest(Builder.Action):

    def run(self, env):
        # ctest must run from the build directory
        build_dir = os.path.join(env.build_dir, 'aws-c-io')
        if os.path.exists(build_dir):
            os.chdir(build_dir)

        return Builder.Script([
            ['ctest', '--output-on-failure', '-R', 'tls_client_'],
        ], name='badssl-test')
