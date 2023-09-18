import Builder

import os
import re
import subprocess


class SetupAsan(Builder.Action):
    def run(self, env):
        self.env = env

        compiler = os.getenv('CC')
        proc = subprocess.run([compiler, '-print-file-name=libclang_rt.asan-x86_64.so'], stdout=subprocess.PIPE)
        proc.check_returncode()
        path = proc.stdout.decode().strip()
        self._setenv('LD_PRELOAD', path)

    def _setenv(self, var, value):
        """
        Set environment variable now,
        and ensure the environment variable is set again when tests run
        """
        self.env.shell.setenv(var, value)
        self.env.project.config['test_env'][var] = value
