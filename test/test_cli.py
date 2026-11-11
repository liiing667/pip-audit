import json
from pathlib import Path

import pretend  # type: ignore
import pytest
from packaging.version import Version

import pip_audit._cli
from pip_audit._cli import (
    OutputFormatChoice,
    ProgressSpinnerChoice,
    VulnerabilityAliasChoice,
    VulnerabilityDescriptionChoice,
    VulnerabilityServiceChoice,
    _is_vuln_ignored,
    _parse_ignore_vulns,
)
from pip_audit._service.interface import (
    ResolvedDependency,
    VulnerabilityResult,
    VulnerabilityService,
)


class TestOutputFormatChoice:
    def test_to_format_is_exhaustive(self):
        for choice in OutputFormatChoice:
            assert choice.to_format(False, False) is not None
            assert choice.to_format(True, True) is not None
            assert choice.to_format(False, True) is not None
            assert choice.to_format(True, False) is not None

    def test_str(self):
        for choice in OutputFormatChoice:
            assert str(choice) == choice.value


class TestVulnerabilityServiceChoice:
    def test_str(self):
        for choice in VulnerabilityServiceChoice:
            assert str(choice) == choice.value


class TestVulnerabilityDescriptionChoice:
    def test_to_bool_is_exhaustive(self):
        for choice in VulnerabilityDescriptionChoice:
            assert choice.to_bool(OutputFormatChoice.Json) in {True, False}

    def test_auto_to_bool_for_json(self):
        assert VulnerabilityDescriptionChoice.Auto.to_bool(OutputFormatChoice.Json) is True

    def test_str(self):
        for choice in VulnerabilityDescriptionChoice:
            assert str(choice) == choice.value


class TestVulnerabilityAliasChoice:
    def test_to_bool_is_exhaustive(self):
        for choice in VulnerabilityAliasChoice:
            assert choice.to_bool(OutputFormatChoice.Json) in {True, False}
            assert choice.to_bool(OutputFormatChoice.Markdown) in {True, False}
            assert choice.to_bool(OutputFormatChoice.Columns) in {True, False}
            assert choice.to_bool(OutputFormatChoice.CycloneDxJson) in {True, False}
            assert choice.to_bool(OutputFormatChoice.CycloneDxXml) in {True, False}

    def test_auto_to_bool_for_json(self):
        assert VulnerabilityAliasChoice.Auto.to_bool(OutputFormatChoice.Json) is True

    def test_str(self):
        for choice in VulnerabilityAliasChoice:
            assert str(choice) == choice.value


class TestProgressSpinnerChoice:
    def test_bool(self):
        assert bool(ProgressSpinnerChoice.On)
        assert not bool(ProgressSpinnerChoice.Off)

    def test_str(self):
        for choice in ProgressSpinnerChoice:
            assert str(choice) == choice.value


@pytest.mark.parametrize(
    "args, vuln_count, pkg_count, expected",
    [
        ([], 1, 1, "Found 1 known vulnerability in 1 package"),
        ([], 2, 1, "Found 2 known vulnerabilities in 1 package"),
        ([], 2, 2, "Found 2 known vulnerabilities in 2 packages"),
        (
            ["--ignore-vuln", "bar"],
            2,
            2,
            "Found 2 known vulnerabilities, ignored 1 in 2 packages",
        ),
        (["--fix"], 1, 1, "fixed 1 vulnerability in 1 package"),
        (["--fix"], 2, 1, "fixed 2 vulnerabilities in 1 package"),
        (["--fix"], 2, 2, "fixed 2 vulnerabilities in 2 packages"),
        ([], 0, 0, "No known vulnerabilities found"),
        (["--ignore-vuln", "bar"], 0, 1, "No known vulnerabilities found, 1 ignored"),
    ],
)
def test_plurals(capsys, monkeypatch, args, vuln_count, pkg_count, expected):
    dummysource = pretend.stub(fix=lambda a: None)
    monkeypatch.setattr(pip_audit._cli, "PipSource", lambda *a, **kw: dummysource)

    parser = pip_audit._cli._parser()
    monkeypatch.setattr(pip_audit._cli, "_parse_args", lambda *a: parser.parse_args(args))

    result = [
        (
            pretend.stub(
                is_skipped=lambda: False,
                name="something" + str(i),
                canonical_name="something" + str(i),
                version=1,
            ),
            [
                pretend.stub(
                    fix_versions=[2],
                    id="foo",
                    aliases=set(),
                    has_any_id=lambda x: False,
                )
            ]
            * (vuln_count // pkg_count),
        )
        for i in range(pkg_count)
    ]

    if "--ignore-vuln" in args:
        result[0][1].append(pretend.stub(id="bar", aliases=set(), has_any_id=lambda x: True))

    auditor = pretend.stub(audit=lambda a: result)
    monkeypatch.setattr(pip_audit._cli, "Auditor", lambda *a, **kw: auditor)

    resolve_fix_versions = [
        pretend.stub(is_skipped=lambda: False, dep=spec, version=2) for spec, _ in result
    ]
    monkeypatch.setattr(pip_audit._cli, "resolve_fix_versions", lambda *a: resolve_fix_versions)

    try:
        pip_audit._cli.audit()
    except SystemExit:
        pass

    captured = capsys.readouterr()
    assert expected in captured.err


@pytest.mark.parametrize(
    "vuln_count, pkg_count, skip_count, print_format",
    [
        (1, 1, 0, True),
        (2, 1, 0, True),
        (2, 2, 0, True),
        (0, 0, 0, False),
        (0, 1, 0, False),
        # If there are no vulnerabilities but a dependency has been skipped, we
        # should print the formatted result
        (0, 0, 1, True),
    ],
)
def test_print_format(monkeypatch, vuln_count, pkg_count, skip_count, print_format):
    dummysource = pretend.stub(fix=lambda a: None)
    monkeypatch.setattr(pip_audit._cli, "PipSource", lambda *a, **kw: dummysource)

    dummyformat = pretend.stub(
        format=pretend.call_recorder(lambda _result, _fixes: None),
        is_manifest=False,
    )
    monkeypatch.setattr(pip_audit._cli, "ColumnsFormat", lambda *a, **kw: dummyformat)

    parser = pip_audit._cli._parser()
    monkeypatch.setattr(pip_audit._cli, "_parse_args", lambda *a: parser.parse_args([]))

    result = [
        (
            pretend.stub(
                is_skipped=lambda: False,
                name="something" + str(i),
                canonical_name="something" + str(i),
                version=1,
            ),
            [
                pretend.stub(
                    fix_versions=[2],
                    id="foo",
                    aliases=set(),
                    has_any_id=lambda x: False,
                )
            ]
            * (vuln_count // pkg_count),
        )
        for i in range(pkg_count)
    ]
    result.extend(
        (
            pretend.stub(
                is_skipped=lambda: True,
                name="skipped " + str(i),
                canonical_name="skipped " + str(i),
                version=1,
                skip_reason="reason " + str(i),
            ),
            [],
        )
        for i in range(skip_count)
    )

    auditor = pretend.stub(audit=lambda a: result)
    monkeypatch.setattr(pip_audit._cli, "Auditor", lambda *a, **kw: auditor)

    resolve_fix_versions = [
        pretend.stub(is_skipped=lambda: False, dep=spec, version=2) for spec, _ in result
    ]
    monkeypatch.setattr(pip_audit._cli, "resolve_fix_versions", lambda *a: resolve_fix_versions)

    try:
        pip_audit._cli.audit()
    except SystemExit:
        pass

    assert bool(dummyformat.format.calls) == print_format


def test_environment_variable(monkeypatch):
    """Environment variables set before execution change CLI option default."""
    monkeypatch.setenv("PIP_AUDIT_DESC", "off")
    monkeypatch.setenv("PIP_AUDIT_FORMAT", "markdown")
    monkeypatch.setenv("PIP_AUDIT_OUTPUT", "/tmp/fake")
    monkeypatch.setenv("PIP_AUDIT_PROGRESS_SPINNER", "off")
    monkeypatch.setenv("PIP_AUDIT_VULNERABILITY_SERVICE", "osv")

    parser = pip_audit._cli._parser()
    monkeypatch.setattr(pip_audit._cli, "_parse_args", lambda *a: parser.parse_args([]))
    args = pip_audit._cli._parse_args(parser, [])

    assert args.desc == VulnerabilityDescriptionChoice.Off
    assert args.format == OutputFormatChoice.Markdown
    assert args.output == Path("/tmp/fake")
    assert not args.progress_spinner
    assert args.vulnerability_service == VulnerabilityServiceChoice.Osv


class _FakeVulnService(VulnerabilityService):
    """
    An offline vulnerability service shared by the package-scoped ignore tests.

    Both `foo` and `bar` report the same CVE (under different primary IDs),
    so package-scoped ignores can be verified against the same vulnerability
    hitting more than one dependency.
    """

    FIXED_VERSION = Version("2.0.0")

    def query(self, spec):
        if spec.name == "foo" and spec.version < self.FIXED_VERSION:
            return spec, [
                VulnerabilityResult(
                    id="GHSA-foo-0000-0000",
                    description="foo result",
                    fix_versions=[self.FIXED_VERSION],
                    aliases={"CVE-2025-0001"},
                )
            ]
        elif spec.name == "bar" and spec.version < self.FIXED_VERSION:
            return spec, [
                VulnerabilityResult(
                    id="GHSA-bar-1111-1111",
                    description="bar result",
                    fix_versions=[self.FIXED_VERSION],
                    aliases={"CVE-2025-0001"},
                )
            ]

        return spec, []


class _FakeDependencySource:
    def __init__(self, deps):
        self._deps = deps
        self.fixed = []

    def collect(self):
        yield from self._deps

    def fix(self, fix_version):
        self.fixed.append(fix_version)


def _run_audit_with_fake_service(monkeypatch, capsys, args):
    """
    Run the CLI `audit()` entrypoint fully offline against `_FakeVulnService`.

    Returns the captured stdout/stderr text and the process exit code.
    """
    deps = [
        ResolvedDependency(name="foo", version=Version("1.0.0")),
        ResolvedDependency(name="bar", version=Version("1.0.0")),
    ]
    source = _FakeDependencySource(deps)
    monkeypatch.setattr(pip_audit._cli, "PipSource", lambda *a, **kw: source)
    monkeypatch.setattr(pip_audit._cli, "PyPIService", lambda *a, **kw: _FakeVulnService())

    parser = pip_audit._cli._parser()
    monkeypatch.setattr(pip_audit._cli, "_parse_args", lambda *a: parser.parse_args(args))

    try:
        pip_audit._cli.audit()
    except SystemExit as exc:
        exit_code = exc.code
    else:
        exit_code = 0

    captured = capsys.readouterr()
    return source, captured, exit_code


def test_parse_ignore_vulns_splits_global_and_scoped_rules():
    global_ignores, package_ignores = _parse_ignore_vulns(
        ["CVE-GLOBAL-1", "Foo.Bar:CVE-SCOPED-1", "foo-bar:CVE-SCOPED-2"]
    )

    assert global_ignores == {"CVE-GLOBAL-1"}
    assert package_ignores == {
        "foo-bar": {"CVE-SCOPED-1", "CVE-SCOPED-2"},
    }


def test_parse_ignore_vulns_keeps_id_only_behavior():
    global_ignores, package_ignores = _parse_ignore_vulns(["CVE-1", "GHSA-2"])

    assert global_ignores == {"CVE-1", "GHSA-2"}
    assert package_ignores == {}


def test_is_vuln_ignored_matches_scoped_alias_on_canonical_name():
    dep = ResolvedDependency(name="Foo.Bar", version=Version("1.0.0"))
    vuln = VulnerabilityResult(
        id="GHSA-aaaa-bbbb-cccc",
        description="fake",
        fix_versions=[Version("2.0.0")],
        aliases={"CVE-2025-0001"},
    )

    assert _is_vuln_ignored(dep, vuln, set(), {"foo-bar": {"CVE-2025-0001"}})
    assert not _is_vuln_ignored(dep, vuln, set(), {"other-pkg": {"CVE-2025-0001"}})
    assert _is_vuln_ignored(dep, vuln, {"CVE-2025-0001"}, {})
    assert not _is_vuln_ignored(dep, vuln, set(), {"foo-bar": {"CVE-2025-9999"}})


def test_cli_package_scoped_ignore_only_suppresses_target_dependency(capsys, monkeypatch):
    _, captured, exit_code = _run_audit_with_fake_service(
        monkeypatch,
        capsys,
        ["--ignore-vuln", "foo:CVE-2025-0001", "--progress-spinner", "off"],
    )

    assert exit_code == 1
    assert "Found 1 known vulnerability, ignored 1 in 1 package" in captured.err

    output = captured.out
    assert "GHSA-bar-1111-1111" in output
    assert "GHSA-foo-0000-0000" not in output


def test_cli_package_scoped_ignore_matches_by_alias_and_noncanonical_name(capsys, monkeypatch):
    _, captured, exit_code = _run_audit_with_fake_service(
        monkeypatch,
        capsys,
        ["--ignore-vuln", "Foo:CVE-2025-0001", "--progress-spinner", "off"],
    )

    assert exit_code == 1
    assert "ignored 1" in captured.err
    assert "GHSA-bar-1111-1111" in captured.out
    assert "GHSA-foo-0000-0000" not in captured.out


def test_cli_global_ignore_still_suppresses_every_dependency(capsys, monkeypatch):
    _, captured, exit_code = _run_audit_with_fake_service(
        monkeypatch,
        capsys,
        ["--ignore-vuln", "CVE-2025-0001", "--progress-spinner", "off"],
    )

    assert exit_code == 0
    assert "No known vulnerabilities found, 2 ignored" in captured.err


def test_cli_package_scoped_ignore_json_output(capsys, monkeypatch):
    _, captured, _ = _run_audit_with_fake_service(
        monkeypatch,
        capsys,
        [
            "--ignore-vuln",
            "foo:CVE-2025-0001",
            "--format",
            "json",
            "--progress-spinner",
            "off",
        ],
    )

    report = json.loads(captured.out)
    dependencies = {dep["name"]: dep for dep in report["dependencies"]}
    assert dependencies["foo"]["vulns"] == []
    assert [vuln["id"] for vuln in dependencies["bar"]["vulns"]] == ["GHSA-bar-1111-1111"]


def test_cli_package_scoped_ignore_with_multiple_requirements(capsys, monkeypatch, tmp_path):
    first_requirements = tmp_path / "first.txt"
    second_requirements = tmp_path / "second.txt"
    first_requirements.write_text("foo==1.0.0\n")
    second_requirements.write_text("bar==1.0.0\n")

    deps = [
        ResolvedDependency(name="foo", version=Version("1.0.0")),
        ResolvedDependency(name="bar", version=Version("1.0.0")),
    ]
    source = _FakeDependencySource(deps)
    captured_kwargs = {}

    def fake_requirement_source(filenames, **kwargs):
        captured_kwargs["filenames"] = filenames
        captured_kwargs["kwargs"] = kwargs
        return source

    monkeypatch.setattr(pip_audit._cli, "RequirementSource", fake_requirement_source)
    monkeypatch.setattr(pip_audit._cli, "PyPIService", lambda *a, **kw: _FakeVulnService())

    parser = pip_audit._cli._parser()
    monkeypatch.setattr(
        pip_audit._cli,
        "_parse_args",
        lambda *a: parser.parse_args(
            [
                "-r",
                str(first_requirements),
                "-r",
                str(second_requirements),
                "--ignore-vuln",
                "foo:CVE-2025-0001",
                "--progress-spinner",
                "off",
            ]
        ),
    )

    try:
        pip_audit._cli.audit()
    except SystemExit as exc:
        exit_code = exc.code
    else:
        exit_code = 0

    assert captured_kwargs["filenames"] == [first_requirements, second_requirements]
    assert exit_code == 1
    captured = capsys.readouterr()
    assert "GHSA-bar-1111-1111" in captured.out
    assert "GHSA-foo-0000-0000" not in captured.out


def test_cli_package_scoped_ignore_with_fix(capsys, monkeypatch):
    source, captured, exit_code = _run_audit_with_fake_service(
        monkeypatch,
        capsys,
        [
            "--ignore-vuln",
            "foo:CVE-2025-0001",
            "--fix",
            "--progress-spinner",
            "off",
        ],
    )

    # Only `bar` still has a vulnerability, so only `bar` is fixed and the
    # run exits zero once every remaining vulnerability has been fixed.
    assert exit_code == 0
    assert [fix.dep.name for fix in source.fixed] == ["bar"]
    assert "fixed 1 vulnerability in 1 package" in captured.err
