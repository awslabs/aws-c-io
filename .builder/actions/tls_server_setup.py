"""
Setup local TLS servers for tests
"""

import Builder

from pathlib import Path
import sys
import subprocess
import atexit


class TlsServerSetup(Builder.Action):
    """
    Set up this machine for running the mock server test

    This action should be run in the 'pre_build_steps' or 'build_steps' stage.
    """

    @staticmethod
    def cleanup_tls_server(tls_server_process):
        tls_server_process.terminate()
        out, err = tls_server_process.communicate()
        print("TLS server stdout:")
        for line in out.splitlines():
            print(f"  = {line.decode('utf-8')}")
        print("TLS server stderr:")
        for line in err.splitlines():
            print(f"  = {line.decode('utf-8')}")

    def run(self, env):
        if not env.project.needs_tests(env):
            print("Skipping TLS server setup because tests disabled for project")
            return

        self.env = env

        root_dir = Path(__file__).resolve().parent / '..' / '..'
        tls_server_dir = root_dir / 'tests' / 'tls_server'
        resource_dir = root_dir / 'tests' / 'resources'

        print("Running TLS servers")

        python_path = env.config['variables']['python']

        tls12_server_process = subprocess.Popen(
            [python_path, tls_server_dir / 'tls_server.py', '--port', '58443', '--resource-dir', resource_dir,
             '--min-tls', '1.2',
             '--max-tls', '1.2'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        tls13_server_process = subprocess.Popen(
            [python_path, tls_server_dir / 'tls_server.py', '--port', '59443', '--resource-dir', resource_dir,
             '--min-tls', '1.3',
             '--max-tls', '1.3'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        @atexit.register
        def close_tls_servers():
            print('Terminating TLS 1.2 server')
            TlsServerSetup.cleanup_tls_server(tls12_server_process)
            print('Terminating TLS 1.3 server')
            TlsServerSetup.cleanup_tls_server(tls13_server_process)
