# Security evidence in planning

Core distinguishes a successful empty advisory result from an affected release
whose severity is not known. A finding without a supported rating stays visible
as a finding and cannot satisfy `no-critical` or `no-high`. The `no-vuln` goal
requires a successful result containing no findings.

## Online OSV

Before a query result enters the per-run cache, Core validates the entire
positional response, every advisory reference, and each detail's requested ID.
A malformed response, an explicit error, a result-count mismatch or an unfinished
page is unavailable evidence. None of these states is stored as an empty finding
list. Existing malformed in-memory entries are discarded before a fresh lookup.
Batch pairs are published together only after their details have passed validation.

OSV details may omit severity. This is valid incomplete evidence, and the positive
finding is retained. Online diagnostics expose `UNKNOWN` with a fixed reason such
as `MISSING_SEVERITY`, `INVALID_SEVERITY` or `UNSUPPORTED_SEVERITY_TYPE`.

## Severity and package scope

`security_evidence.py` uses the separately installed, exact dependency
`cvss==3.6` to validate and score CVSS V2, V3.0, V3.1 and V4.0 vectors. A numeric
string is not substituted for the vector required by the OSV schema. Missing,
duplicate or invalid vector metrics fail closed.

Core uses base severity, without assuming environmental or threat mitigations
for the user's project. The highest supported rating is retained. An additional
unsupported or invalid rating keeps the assessment incomplete; a known low rating
cannot make the unknown rating safe. A known high or critical finding remains
visible even when another supplied rating cannot be interpreted.

The compact summary uses `U` for findings with an incomplete severity assessment.
A partially rated finding retains its known category and also increments `U`:
`L:1, U:1` can describe one advisory, not two. The diagnostic `findingCount` is
the advisory count. This preserves positive observations while carrying
incompleteness through the exact-version Fast gate, final enrichment and plan
projection. A projection with `U` is unknown even if its known C/H counts are zero.

Package-specific `affected[].severity` is evaluated for the explicitly queried
`npm` package. A caller without that package context receives incomplete evidence.
Conflicting top-level and package-specific severity fields are rejected. Registry
and offline OSV results pass through the same security-goal predicate; offline
snapshot freshness, private-scope exclusions and fallback protections are unchanged.

Sources:

- [OSV severity contract](https://ossf.github.io/osv-schema/#severity-field)
- [CVSS parser source and license](https://github.com/RedHatProductSecurity/cvss)
- [Pinned parser distribution](https://pypi.org/project/cvss/3.6/)

The parser is a separate LGPLv3+ runtime dependency, with its original license
metadata retained in the installed distribution. Its universal wheel SHA-256 is
`e342c6ad9c7eb69d2aebbbc2768a03cabd57eb947c806e145de5b936219833ea` and it has no
runtime dependencies of its own.

## Regression checks

`tests/test_online_security_evidence.py` exercises real loopback HTTP responses
through the planner, malformed batch/detail responses, cache recovery, supported
CVSS vectors, package scope and explicit low/clean controls. It makes no requests
to public npm or OSV and does not install a project dependency. The existing
`test_osv_offline.py`, `test_osv_detail_prefetch.py` and registry identity tests
cover offline fallback, deadline behavior and registry-cache boundaries.
