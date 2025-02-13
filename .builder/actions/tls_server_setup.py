"""
Setup local TLS server for tests
"""

import Builder

import os
import sys
import subprocess
import atexit
import time


class TlsServerSetup(Builder.Action):
    """
    Set up this machine for running the mock server test

    This action should be run in the 'pre_build_steps' or 'build_steps' stage.
    """

    def run(self, env):
        if not env.project.needs_tests(env):
            print("Skipping TLS server setup because tests disabled for project")
            return

        self.env = env

        base_dir = os.path.dirname(os.path.realpath(__file__))
        dir = os.path.join(base_dir, "..", "..", "tests", "tls_server")

        print("Running openssl TLS server")

        python_path = sys.executable
        p = subprocess.Popen([python_path, "tls_server.py",
                              ], cwd=dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        @atexit.register
        def close_tls_server():
            print("Terminating openssl TLS server")
            p.terminate()
            out, err = p.communicate()
            print("TLS server stdout:\n{}".format(out))
            print("TLS server stderr:\n{}".format(err))
