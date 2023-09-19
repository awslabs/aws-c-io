"""
Setup LD_LIBRARY_PATH for shared libasan.
"""

import Builder

import os
import subprocess


class SetupClangLibasanPath(Builder.Action):
    """
    The path to the shared asan library is not added to runpath.
    This action sets LD_LIBRARY_PATH to help find it.
    """
    def run(self, env):
        self.env = env

        compiler = os.getenv('CC')
        # NOTE The arch is hard-coded since the issue with static libasan is present only
        # in x86_64 Ubuntu-based distros.
        proc = subprocess.run([compiler, '-print-file-name=libclang_rt.asan-x86_64.so'], stdout=subprocess.PIPE)
        proc.check_returncode()

        path = os.path.dirname(proc.stdout.decode().strip())
        self._addpathenv('LD_LIBRARY_PATH', path)

    def _addpathenv(self, var, path):
        """Add a path to an environment variable"""
        prev = os.getenv(var)
        if prev:
            value = prev + os.pathsep + path
        else:
            value = path

        self.env.shell.setenv(var, value)
        self.env.project.config['test_env'][var] = value
