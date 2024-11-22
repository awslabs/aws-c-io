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

        p1 = subprocess.Popen(["openssl.exe", "s_server",
                               "-accept", "1443",
                               "-key", "server.key",
                               "-cert", "server.crt",
                               "-CAfile", "server_chain.crt",
                               "-alpn", "x-amzn-mqtt-ca",
                               "-tls1_3",  # Allow TLS 1.3 connections only
                               "-verify", "1"  # Verify client's certificate
                               ], cwd=dir, stdout=sys.stdout, stderr=sys.stdout)
        time.sleep(1)
        p1.poll()
        print("Return code is {}".format(p1.returncode))

        @atexit.register
        def close_tls_server():
            print("Terminating openssl TLS server")
            p1.terminate()
