"""CLI behaviour and exit codes."""

import json

from licenseengine.cli import main


def write(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text)
    return p


class TestExitCodes:
    def test_clean_manifest_exits_zero(self, tmp_path):
        p = write(tmp_path, "requirements.txt", "nothing-at-all\n")
        # No licence data at all -> every component blocks, so --check fails.
        assert main([str(p), "--check"]) == 1

    def test_passing_manifest_exits_zero_with_check(self, tmp_path):
        p = write(tmp_path, "package-lock.json", json.dumps({
            "lockfileVersion": 2,
            "packages": {"node_modules/a": {"version": "1", "license": "MIT"}},
        }))
        assert main([str(p), "--check"]) == 0

    def test_missing_manifest_exits_two(self, tmp_path):
        assert main([str(tmp_path / "absent.json")]) == 2

    def test_unknown_manifest_type_exits_two(self, tmp_path):
        p = write(tmp_path, "deps.qqq", "x")
        assert main([str(p)]) == 2


class TestOutput:
    def test_json_output_is_valid(self, tmp_path, capsys):
        p = write(tmp_path, "package-lock.json", json.dumps({
            "lockfileVersion": 2,
            "packages": {
                "node_modules/a": {"version": "1", "license": "MIT"},
                "node_modules/b": {"version": "2", "license": "GPL-3.0-only"},
            },
        }))
        main([str(p), "--json"])
        payload = json.loads(capsys.readouterr().out)
        assert payload["verdict"] == "fail"
        assert payload["components"] == 2

    def test_quiet_prints_one_line(self, tmp_path, capsys):
        p = write(tmp_path, "package-lock.json", json.dumps({
            "lockfileVersion": 2,
            "packages": {"node_modules/a": {"version": "1", "license": "MIT"}},
        }))
        main([str(p), "--quiet"])
        out = capsys.readouterr().out.strip()
        assert out.count("\n") == 0
        assert "1 component" in out

    def test_human_output_names_the_remedy(self, tmp_path, capsys):
        p = write(tmp_path, "package-lock.json", json.dumps({
            "lockfileVersion": 2,
            "packages": {"node_modules/g": {"version": "1", "license": "GPL-3.0-only"}},
        }))
        main([str(p)])
        out = capsys.readouterr().out
        assert "g" in out
        assert "fix:" in out

    def test_transitive_component_is_labelled(self, tmp_path, capsys):
        p = write(tmp_path, "package-lock.json", json.dumps({
            "lockfileVersion": 2,
            "packages": {
                "node_modules/a/node_modules/b": {"version": "1", "license": "GPL-3.0"},
            },
        }))
        main([str(p)])
        assert "transitive" in capsys.readouterr().out


class TestFlags:
    def test_allow_copyleft_flag_clears_the_block(self, tmp_path):
        p = write(tmp_path, "package-lock.json", json.dumps({
            "lockfileVersion": 2,
            "packages": {"node_modules/g": {"version": "1", "license": "GPL-3.0-only"}},
        }))
        assert main([str(p), "--check"]) == 1
        assert main([str(p), "--check", "--allow-copyleft"]) == 0

    def test_deny_flag_blocks_a_normally_fine_licence(self, tmp_path):
        p = write(tmp_path, "package-lock.json", json.dumps({
            "lockfileVersion": 2,
            "packages": {"node_modules/a": {"version": "1", "license": "MIT"}},
        }))
        assert main([str(p), "--check", "--deny", "MIT"]) == 1

    def test_max_depth_flag_warns(self, tmp_path, capsys):
        p = write(tmp_path, "package-lock.json", json.dumps({
            "lockfileVersion": 2,
            "packages": {
                "node_modules/a/node_modules/b/node_modules/c": {
                    "version": "1", "license": "MIT"},
            },
        }))
        main([str(p), "--max-depth", "1"])
        assert "depth" in capsys.readouterr().out.lower()
