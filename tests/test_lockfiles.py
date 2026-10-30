import json
import tempfile
import unittest
from pathlib import Path

from engine import ingest, lockfiles


def by_name(deps):
    return {d["name"]: d for d in deps}


class LockfileParserTest(unittest.TestCase):
    def test_yarn_v1(self):
        text = '''# yarn lockfile v1
"@babel/core@^7.0.0", "@babel/core@^7.1.0":
  version "7.12.3"
  resolved "https://registry.yarnpkg.com/@babel/core/-/core-7.12.3.tgz"

lodash@^4.17.0:
  version "4.17.21"
'''
        deps = by_name(lockfiles.parse_yarn_lock(text))
        self.assertEqual(deps["@babel/core"]["version"], "7.12.3")
        self.assertEqual(deps["lodash"]["version"], "4.17.21")
        self.assertEqual(deps["lodash"]["ecosystem"], "npm")

    def test_yarn_berry(self):
        text = '''__metadata:
  version: 6

"minimist@npm:^1.2.5":
  version: 1.2.8
  resolution: "minimist@npm:1.2.8"
'''
        deps = by_name(lockfiles.parse_yarn_lock(text))
        self.assertEqual(deps["minimist"]["version"], "1.2.8")

    def test_pnpm_v9_and_peer_suffix(self):
        text = '''lockfileVersion: '9.0'
packages:
  lodash@4.17.21:
    resolution: {integrity: sha512-x}
  react-dom@18.2.0(react@18.2.0):
    resolution: {integrity: sha512-y}
'''
        deps = by_name(lockfiles.parse_pnpm_lock(text))
        self.assertEqual(deps["lodash"]["version"], "4.17.21")
        self.assertEqual(deps["react-dom"]["version"], "18.2.0")

    def test_poetry_marks_dev_scope(self):
        text = '''[[package]]
name = "Django"
version = "4.2.1"
category = "main"

[[package]]
name = "pytest"
version = "8.0.0"
category = "dev"
'''
        deps = by_name(lockfiles.parse_poetry_lock(text))
        self.assertEqual(deps["django"]["version"], "4.2.1")
        self.assertEqual(deps["pytest"]["scope"], "dev")

    def test_uv(self):
        text = '''version = 1

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
'''
        self.assertEqual(lockfiles.parse_uv_lock(text)[0]["version"], "2.31.0")

    def test_pipfile_requires_pins(self):
        data = json.dumps({"default": {"Flask": {"version": "==2.3.2"}},
                           "develop": {"pytest": {"version": "==8.0.0"}}})
        deps = by_name(lockfiles.parse_pipfile_lock(data))
        self.assertEqual(deps["flask"]["version"], "2.3.2")
        self.assertEqual(deps["pytest"]["scope"], "dev")
        with self.assertRaises(ValueError):
            lockfiles.parse_pipfile_lock(json.dumps({"default": {"x": {"version": "*"}}}))

    def test_go_sum_skips_go_mod_hashes(self):
        text = '''github.com/gin-gonic/gin v1.9.1 h1:abc=
github.com/gin-gonic/gin v1.9.1/go.mod h1:def=
'''
        deps = lockfiles.parse_go_sum(text)
        self.assertEqual(len(deps), 1)
        self.assertEqual(deps[0]["name"], "github.com/gin-gonic/gin")
        self.assertEqual(deps[0]["version"], "v1.9.1")

    def test_cargo_skips_workspace_members(self):
        text = '''[[package]]
name = "app"
version = "0.1.0"

[[package]]
name = "serde"
version = "1.0.197"
source = "registry+https://github.com/rust-lang/crates.io-index"
'''
        deps = lockfiles.parse_cargo_lock(text)
        self.assertEqual([d["name"] for d in deps], ["serde"])
        self.assertEqual(deps[0]["ecosystem"], "crates.io")

    def test_composer_strips_v_prefix(self):
        data = json.dumps({"packages": [{"name": "monolog/monolog", "version": "v2.9.1"}],
                           "packages-dev": [{"name": "phpunit/phpunit", "version": "10.5.0"}]})
        deps = by_name(lockfiles.parse_composer_lock(data))
        self.assertEqual(deps["monolog/monolog"]["version"], "2.9.1")
        self.assertEqual(deps["phpunit/phpunit"]["scope"], "dev")

    def test_gemfile_lock_specs_only(self):
        text = '''GEM
  remote: https://rubygems.org/
  specs:
    rack (2.2.8)
    rails (7.1.3)
      actionpack (= 7.1.3)

PLATFORMS
  ruby
'''
        deps = by_name(lockfiles.parse_gemfile_lock(text))
        self.assertEqual(deps["rack"]["version"], "2.2.8")
        self.assertEqual(deps["rails"]["version"], "7.1.3")
        self.assertNotIn("actionpack", deps)

    def test_nuget_lock(self):
        data = json.dumps({"version": 1, "dependencies": {"net8.0": {
            "Newtonsoft.Json": {"type": "Direct", "resolved": "13.0.1"},
            "System.Text.Json": {"type": "Transitive", "resolved": "8.0.0"}}}})
        deps = by_name(lockfiles.parse_nuget_lock(data))
        self.assertEqual(deps["Newtonsoft.Json"]["version"], "13.0.1")
        self.assertEqual(deps["System.Text.Json"]["ecosystem"], "NuGet")


class AutoDetectionTest(unittest.TestCase):
    def test_detects_lockfile_by_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "go.sum").write_text("github.com/a/b v1.0.0 h1:x=\n")
            deps = ingest.resolve(root, None)
            self.assertEqual(deps[0]["ecosystem"], "Go")

    def test_malformed_lockfile_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "Pipfile.lock"
            path.write_text("{not json")
            with self.assertRaises(json.JSONDecodeError):
                ingest.detect_and_parse(path)


if __name__ == "__main__":
    unittest.main()
