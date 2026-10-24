"""Manifest readers."""

import json

import pytest

from licenseengine.readers import (
    ManifestError,
    read_go_mod,
    read_manifest,
    read_npm,
    read_pyproject,
    read_requirements,
)


class TestNpm:
    def test_lockfile_v2_reads_the_packages_map(self, tmp_path):
        lock = {
            "name": "app",
            "lockfileVersion": 2,
            "packages": {
                "": {"name": "app", "version": "1.0.0"},
                "node_modules/left-pad": {
                    "version": "1.3.0", "license": "MIT",
                },
                "node_modules/ms": {"version": "2.1.3", "license": "MIT"},
            },
        }
        p = tmp_path / "package-lock.json"
        p.write_text(json.dumps(lock))
        comps = read_npm(p)
        assert {c.name for c in comps} == {"left-pad", "ms"}
        assert all(c.license_expression == "MIT" for c in comps)
        assert all(c.ecosystem == "npm" for c in comps)

    def test_root_package_is_skipped(self, tmp_path):
        lock = {"lockfileVersion": 2, "packages": {"": {"name": "app"}, "node_modules/a":
                {"version": "1", "license": "MIT"}}}
        p = tmp_path / "package-lock.json"
        p.write_text(json.dumps(lock))
        assert [c.name for c in read_npm(p)] == ["a"]

    def test_nested_dependency_is_marked_transitive(self, tmp_path):
        lock = {
            "lockfileVersion": 2,
            "packages": {
                "node_modules/a": {"version": "1", "license": "MIT"},
                "node_modules/a/node_modules/b": {"version": "2", "license": "ISC"},
            },
        }
        p = tmp_path / "package-lock.json"
        p.write_text(json.dumps(lock))
        by_name = {c.name: c for c in read_npm(p)}
        assert by_name["a"].direct is True
        assert by_name["b"].direct is False
        assert by_name["b"].depth >= 1

    def test_lockfile_v1_walks_the_tree(self, tmp_path):
        lock = {
            "lockfileVersion": 1,
            "dependencies": {
                "a": {"version": "1", "license": "MIT",
                      "dependencies": {"b": {"version": "2", "license": "ISC"}}},
            },
        }
        p = tmp_path / "package-lock.json"
        p.write_text(json.dumps(lock))
        by_name = {c.name: c for c in read_npm(p)}
        assert by_name["a"].direct is True
        assert by_name["b"].direct is False
        assert by_name["b"].license_expression == "ISC"

    def test_list_licence_is_joined_with_and(self, tmp_path):
        lock = {"lockfileVersion": 2, "packages": {
            "node_modules/x": {"version": "1", "license": ["MIT", "Apache-2.0"]}}}
        p = tmp_path / "package-lock.json"
        p.write_text(json.dumps(lock))
        assert read_npm(p)[0].license_expression == "MIT AND Apache-2.0"

    def test_missing_licence_field_yields_empty_expression(self, tmp_path):
        lock = {"lockfileVersion": 2, "packages": {"node_modules/x": {"version": "1"}}}
        p = tmp_path / "package-lock.json"
        p.write_text(json.dumps(lock))
        assert read_npm(p)[0].license_expression == ""

    def test_malformed_json_raises(self, tmp_path):
        p = tmp_path / "package-lock.json"
        p.write_text("{not json")
        with pytest.raises(json.JSONDecodeError):
            read_npm(p)


class TestRequirements:
    def test_simple_lines(self, tmp_path):
        p = tmp_path / "requirements.txt"
        p.write_text("requests==2.31.0\nflask>=2.0\n")
        assert [c.name for c in read_requirements(p)] == ["requests", "flask"]

    def test_extras_are_stripped(self, tmp_path):
        p = tmp_path / "requirements.txt"
        p.write_text("uvicorn[standard]==0.30.0\n")
        assert read_requirements(p)[0].name == "uvicorn"

    def test_environment_marker_is_ignored(self, tmp_path):
        p = tmp_path / "requirements.txt"
        p.write_text('tomli==2.0.1; python_version < "3.11"\n')
        assert read_requirements(p)[0].name == "tomli"

    def test_comments_and_blank_lines_are_skipped(self, tmp_path):
        p = tmp_path / "requirements.txt"
        p.write_text("# a comment\n\n   \nflask\n")
        assert [c.name for c in read_requirements(p)] == ["flask"]

    def test_include_directives_are_skipped(self, tmp_path):
        p = tmp_path / "requirements.txt"
        p.write_text("-r base.txt\n--index-url https://example.com\nflask\n")
        assert [c.name for c in read_requirements(p)] == ["flask"]

    def test_hash_pinned_line_still_yields_the_name(self, tmp_path):
        p = tmp_path / "requirements.txt"
        p.write_text("flask==2.0.1 --hash=sha256:deadbeef\n")
        assert read_requirements(p)[0].name == "flask"

    def test_requirements_carry_no_licence(self, tmp_path):
        """A requirements file cannot prove licensing, so the field stays empty."""
        p = tmp_path / "requirements.txt"
        p.write_text("flask\n")
        assert read_requirements(p)[0].license_expression == ""


class TestPyproject:
    def test_pep621_dependencies(self, tmp_path):
        p = tmp_path / "pyproject.toml"
        p.write_text(
            '[project]\nname = "x"\ndependencies = [\n  "requests>=2",\n  "flask",\n]\n'
        )
        assert sorted(c.name for c in read_pyproject(p)) == ["flask", "requests"]

    def test_poetry_dependencies(self, tmp_path):
        p = tmp_path / "pyproject.toml"
        p.write_text(
            '[tool.poetry.dependencies]\npython = "^3.11"\nrequests = "^2.0"\n'
        )
        names = [c.name for c in read_pyproject(p)]
        assert "requests" in names
        assert "python" not in names, "the interpreter is not a licence concern"

    def test_specifiers_are_stripped(self, tmp_path):
        p = tmp_path / "pyproject.toml"
        p.write_text('[project]\ndependencies = ["requests[security]>=2.0; extra == \'x\'"]\n')
        assert read_pyproject(p)[0].name == "requests"

    def test_duplicates_collapse(self, tmp_path):
        p = tmp_path / "pyproject.toml"
        p.write_text('[project]\ndependencies = ["flask", "Flask>=2"]\n')
        assert len(read_pyproject(p)) == 1


class TestGoMod:
    def test_block_form(self, tmp_path):
        p = tmp_path / "go.mod"
        p.write_text(
            "module example.com/x\n\ngo 1.21\n\nrequire (\n"
            "\tgithub.com/stretchr/testify v1.9.0\n"
            "\tgolang.org/x/net v0.24.0\n)\n"
        )
        comps = read_go_mod(p)
        assert {c.name for c in comps} == {
            "github.com/stretchr/testify", "golang.org/x/net"
        }
        assert comps[0].ecosystem == "golang"

    def test_single_line_require(self, tmp_path):
        p = tmp_path / "go.mod"
        p.write_text("module x\n\nrequire github.com/pkg/errors v0.9.1\n")
        assert read_go_mod(p)[0].name == "github.com/pkg/errors"

    def test_indirect_comment_is_ignored(self, tmp_path):
        p = tmp_path / "go.mod"
        p.write_text("require (\n\tgithub.com/a/b v1.0.0 // indirect\n)\n")
        comps = read_go_mod(p)
        assert len(comps) == 1
        assert comps[0].version == "v1.0.0"


class TestDispatch:
    def test_known_filenames_route(self, tmp_path):
        p = tmp_path / "requirements.txt"
        p.write_text("flask\n")
        assert read_manifest(p)[0].name == "flask"

    def test_unknown_filename_raises_with_a_helpful_message(self, tmp_path):
        p = tmp_path / "deps.xyz"
        p.write_text("nothing useful here")
        with pytest.raises(ManifestError) as exc:
            read_manifest(p)
        assert "unsupported" in str(exc.value)

    def test_renamed_lockfile_is_sniffed(self, tmp_path):
        """Lockfiles get copied and renamed; content should still be recognised."""
        p = tmp_path / "demo-lock.json"
        p.write_text(json.dumps({
            "lockfileVersion": 2,
            "packages": {"node_modules/a": {"version": "1", "license": "MIT"}},
        }))
        assert read_manifest(p)[0].name == "a"

    def test_renamed_go_mod_is_sniffed(self, tmp_path):
        p = tmp_path / "old.mod"
        p.write_text("module x\n\ngo 1.21\n\nrequire github.com/a/b v1.0.0\n")
        assert read_manifest(p)[0].name == "github.com/a/b"

    def test_renamed_pyproject_is_sniffed(self, tmp_path):
        p = tmp_path / "pyproject.bak"
        p.write_text('[project]\nname = "x"\ndependencies = ["flask"]\n')
        assert read_manifest(p)[0].name == "flask"

    def test_binary_file_is_rejected_not_crashed(self, tmp_path):
        p = tmp_path / "blob.bin"
        p.write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR")
        with pytest.raises(ManifestError):
            read_manifest(p)

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(ManifestError):
            read_manifest(tmp_path / "nope.json")
