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
        dir = os.path.join(base_dir, "..", "..", "tests", "resources")

        print("Running openssl TLS server")

        python_path = sys.executable
        p = subprocess.Popen([python_path, "main.py",
                              ], cwd=dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        @atexit.register
        def close_tls_server():
            print("Terminating openssl TLS server")
            p.terminate()
            out, err = p.communicate()
            print("=== stdout:\n{}".format(out))
            # for c in iter(lambda: p.stdout.read(1), b""):
            # sys.stdout.buffer.write(c)
            print("=== stderr:\n{}".format(err))
            # for c in iter(lambda: p.stderr.read(1), b""):
            # sys.stdout.buffer.write(c)
            print("====== bye")
