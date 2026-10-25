"""python/requirements.lock is the resolved, hash-locked form of requirements.txt.

requirements.txt declares the engine's dependencies; the lock is the exact set
the composite Action installs (with --require-hashes) for a Fendix release's
own Python tree, and the set the official images install. These checks run on
the committed files only: regenerating the lock is a deliberate maintenance
step,

    sh scripts/release/regenerate-python-lock.sh

never something CI does.
"""
import hashlib
from pathlib import Path
import re
import unittest

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import Version

PYTHON = Path(__file__).resolve().parents[1]
DECLARED = PYTHON / "requirements.txt"
LOCK = PYTHON / "requirements.lock"
MARK = "# Resolved from python/requirements.txt sha256:"
REGENERATE = "run sh scripts/release/regenerate-python-lock.sh"
# The Semgrep/MCP/Pydantic line v3.6.5 ships (v3.6.1 to v3.6.4 shipped
# 1.141.0/1.16.0/2.13.5). Moving it is a deliberate dependency-line upgrade
# (#111), made by changing this table with the lock.
PROVEN_LINE = {"semgrep": "1.182.1", "mcp": "1.29.0", "pydantic": "2.13.5"}
# Both images install the lock rather than requirements.txt, so they carry the
# versions the Action installs and the Action smoke validates.
IMAGE_DOCKERFILES = ("Dockerfile", "Dockerfile.app")


def declared_requirements():
    for line in DECLARED.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            yield Requirement(line)


def locked_pins():
    """{canonical name: (version, [sha256 hashes])} from pip-compile output."""
    pins, current = {}, None
    for raw in LOCK.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if raw[0] not in " \t":
            match = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;\\]+)\s*\\?", line)
            if not match:
                raise AssertionError(f"requirements.lock has a line that is not an exact pin: {raw!r}")
            current = canonicalize_name(match.group(1))
            pins[current] = (match.group(2), [])
        else:
            pins[current][1].extend(re.findall(r"--hash=sha256:([0-9a-f]{64})", line))
    return pins


class RequirementsLockTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pins = locked_pins()

    def test_lock_was_resolved_from_the_current_declaration(self):
        first = LOCK.read_text().splitlines()[0]
        digest = hashlib.sha256(DECLARED.read_bytes()).hexdigest()
        self.assertEqual(first, MARK + digest, f"requirements.txt changed since the lock was resolved; {REGENERATE}")

    def test_every_pin_is_exact_and_hashed(self):
        self.assertGreater(len(self.pins), 0)
        for name, (version, hashes) in self.pins.items():
            with self.subTest(package=name):
                self.assertTrue(hashes, f"{name}=={version} has no --hash; {REGENERATE}")

    def test_lock_satisfies_every_declared_requirement(self):
        for requirement in declared_requirements():
            with self.subTest(requirement=str(requirement)):
                name = canonicalize_name(requirement.name)
                self.assertIn(name, self.pins, f"{requirement} is declared but not locked; {REGENERATE}")
                version = self.pins[name][0]
                self.assertTrue(requirement.specifier.contains(version, prereleases=True),
                                f"locked {name}=={version} does not satisfy {requirement}; {REGENERATE}")

    def test_pydantic_stays_below_2_14(self):
        self.assertLess(Version(self.pins["pydantic"][0]), Version("2.14"))

    def test_holds_the_proven_semgrep_line(self):
        for name, version in PROVEN_LINE.items():
            with self.subTest(package=name):
                self.assertEqual(self.pins[name][0], version)

    def test_images_install_the_lock_with_hashes(self):
        for name in IMAGE_DOCKERFILES:
            with self.subTest(dockerfile=name):
                text = (PYTHON.parent / name).read_text()
                self.assertIn("COPY python/requirements.lock /tmp/requirements.lock", text)
                install = re.search(r"pip install[^\n]*", text.replace("\\\n", " "))
                self.assertIsNotNone(install, f"{name} has no pip install")
                for flag in ("--require-hashes", "--only-binary=:all:", "-r /tmp/requirements.lock"):
                    self.assertIn(flag, install.group(0))
                self.assertNotIn("requirements.txt", text)


if __name__ == "__main__":
    unittest.main()
