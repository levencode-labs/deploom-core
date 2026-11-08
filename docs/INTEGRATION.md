# Deploom Core ↔ Deploom MCP integration

[Core](https://github.com/levencode-labs/deploom-core) is developed in its own repository. [MCP](https://github.com/levencode-labs/deploom-mcp) pins an exact Core revision at `upstream/deploom` and packages the verified inventory into the published wheel.

## Updating the pinned Core (maintainers)

1. Make and verify the Core change in **deploom-core**. Record the exact commit SHA and its own CI/evidence.
2. Review the MCP `.gitmodules` origin and `upstream/deploom` gitlink. The new canonical repository URL is `https://github.com/levencode-labs/deploom-core.git`. A submodule URL rewrite is a **separate engineering change**, not part of cosmetic documentation updates.
3. Update to the approved Core commit only; do not edit Core files inside the MCP submodule.
4. Regenerate the exact content inventory and other derived integrity records using MCP's documented release scripts. Preserve schema and canonical Skill integrity requirements.
5. Run the MCP source tests, stdio protocol smoke, installed-wheel checks, and required Windows/Linux gates at the pinned revision.
6. Keep runtime and migration acceptance separate from a successful build or planner result. A Draft is not an installed migration.

Do not simply replace hashes in `release-manifest.json`: the manifest must be regenerated from the staged gitlink and real contents. When Core is private, repository-scoped CI credentials may not be able to fetch it; confirm cross-repository checkout access without exposing private source through the wheel.

[Full release procedure](https://github.com/levencode-labs/deploom-mcp/blob/main/docs/RELEASING.md) · [Execution boundary](https://github.com/levencode-labs/deploom-mcp/blob/main/docs/GOAL_EXECUTION_SUPPORT.md)
