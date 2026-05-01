"""
Prepare for custom root CA tests on macOS.
"""

import Builder

from pathlib import Path


class CustomKeychainTestSetup(Builder.Action):
    """
    Create and populate a custom keychain for testing.
    The actual logic is implemented in $ROOT/tests/resources/import_custom_cert_to_keychain.sh since shell commands
    are more suitable for this.

    This action should be run in the 'pre_build_steps' or 'build_steps' stage.
    """

    def run(self, env):
        if not env.project.needs_tests(env):
            print("Skipping Custom Keychain Test setup because tests disabled for project")
            return

        self.env = env

        root_dir = Path(__file__).resolve().parent / '..' / '..'
        resource_dir = root_dir / 'tests' / 'resources'

        env.shell.exec(["bash", "import_custom_cert_to_keychain.sh"], working_dir=resource_dir, check=True)
