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


        p1 = subprocess.Popen(["openssl.exe", "version", "-a",
                              ], cwd=dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(1)
        p1.poll()
        print("Return code for p1 is {}".format(p1.returncode))
        print("=== stdout 1:")
        for c in iter(lambda: p1.stdout.read(1), b""):
            sys.stdout.buffer.write(c)
        print("=== stderr 1:")
        for c in iter(lambda: p1.stderr.read(1), b""):
            sys.stdout.buffer.write(c)

        p = subprocess.Popen(["openssl.exe", "s_server",
                               "-accept", "localhost:59443",
                               "-key", "tls13.key",
                               "-cert", "tls13.pem.crt",
                               "-chainCAfile", "tls13_root_ca.pem.crt",
                               "-alpn", "x-amzn-mqtt-ca",
                               "-debug", "-state",
                               ], cwd=dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(1)
        p.poll()
        print("Return code is {}".format(p.returncode))

        p2 = subprocess.Popen(["openssl.exe", "s_client",
                               "-connect", "localhost:59443",
                               "-debug", "-state",
                               "-servername", "localhost",
                               ], cwd=dir, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        p2.poll()
        print("client Return code is {}".format(p2.returncode))

        out2, err2 = p2.communicate(input=b'Q')
        print("=== client stdout:\n{}".format(out2))
        print("=== client stderr:\n{}".format(err2))

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
