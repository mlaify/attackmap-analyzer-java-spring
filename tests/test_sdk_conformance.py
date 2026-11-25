"""SDK 1.0 conformance (mlaify/AttackMap#254): attackmap.sdk.testing.assert_conforms."""

from pathlib import Path

from attackmap.sdk.testing import assert_conforms

from attackmap_analyzer_java_spring import JavaSpringAnalyzer


def _has_signals(result) -> None:
    assert any(isinstance(v, list) and v for v in result.__dict__.values()), "the analyzer emitted nothing"


SAMPLE = {'pom.xml': '<project><modelVersion>4.0.0</modelVersion><groupId>x</groupId><artifactId>s</artifactId><version>1</version></project>\n', 'src/main/java/UserController.java': '@RestController\npublic class UserController {\n    @GetMapping("/users/{id}")\n    public String user(@PathVariable String id) { return id; }\n}\n'}


def test_conforms_to_the_sdk(tmp_path: Path) -> None:
    for rel, text in SAMPLE.items():
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text(text, encoding="utf-8")
    _has_signals(assert_conforms(JavaSpringAnalyzer(), tmp_path))
