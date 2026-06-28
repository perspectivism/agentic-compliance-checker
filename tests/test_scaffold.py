"""Scaffold smoke test.

Proves the package imports and the CLI wiring is intact, so `pytest` is green from
day one (an empty suite exits non-zero and would make CI red). Keep this permanently —
it doubles as an import canary: if the src/ layout or the CLI parser breaks, the fast
lane fails loudly.
"""

from agentic_compliance.cli import build_parser


def test_cli_parser_builds():
    """The CLI parser constructs with the expected program name."""
    parser = build_parser()
    assert parser.prog == "agentic-compliance"


def test_cli_subcommands_parse():
    """Each subcommand parses and is wired to a handler."""
    parser = build_parser()
    for argv in (["assess", "--repo-path", "."], ["ingest-controls"], ["eval"]):
        args = parser.parse_args(argv)
        assert hasattr(args, "func")
