"""
Setup local badssl.com Docker instance for TLS tests (Linux only).
"""

import Builder

from pathlib import Path
import subprocess


class BadsslSetup(Builder.Action):
    """
    Clone badssl.com, generate certs, build and run the Docker container,
    and install the CA root into the system trust store.

    This action should be run in the 'pre_build_steps' stage.
    """

    def run(self, env):
        if not env.project.needs_tests(env):
            print("Skipping badssl setup because tests disabled for project")
            return

        root_dir = Path(__file__).resolve().parent / '..' / '..'
        setup_script = root_dir / 'setup_badssl.py'

        if not setup_script.exists():
            print(f"WARNING: {setup_script} not found. badssl tests may fail.")
            return

        python_path = env.config['variables']['python']
        print("Setting up local badssl.com...")
        env.shell.exec('sudo', python_path, str(setup_script), check=True)
