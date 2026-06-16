# API reference

Auto-generated from the source docstrings. The public surface is small: a unified **adapter** layer
for targets, and a **probes** layer for attack cases, detectors and scans.

## Adapters

The provider-agnostic target layer. `get_adapter` builds an adapter; vendor SDKs import lazily.

::: llmsectest.adapters
    options:
      show_submodules: false
      members:
        - get_adapter
        - available_providers
        - register_adapter
        - LLMAdapter
        - CompletionRequest
        - CompletionResponse
        - Message
        - Role

### Application endpoint target

::: llmsectest.adapters.app_endpoint

## Probes

Attack cases, target resolution, the runner, application-mode scans, the
white-box LLM03 supply-chain scanner, and the LLM01 red-team set.

::: llmsectest.probes
    options:
      members:
        - ProbeCase
        - ProbeOutcome
        - resolve_target
        - run_probe
        - app_cases
        - app_coverage
        - run_app_scan
        - AppScanResult
        - CategoryCoverage
        - cases_for
        - covered_categories
        - get_detector
        - register_detector
        - available_detectors
        - redteam_cases
        - load_redteam_set
        - builtin_behaviors
        - RedTeamBehavior
        - benign_cases
        - load_benign_set
        - builtin_benign
        - measure_false_refusal
        - FalseRefusalReport
        - scan_dependencies
        - discover_manifests
        - collect_dependencies
        - SupplyChainFinding
        - Dependency
        - scan_known_vulnerabilities
        - pinned_version
        - OsvScanResult

### Red-team detectors

The refusal oracle that scores the red-team set (inverted polarity: a target is
a finding when it complies with a harmful request instead of refusing it), and
its mirror image — the over-refusal oracle that flags a refusal of a *benign*
twin (the false-refusal-rate metric, a usability signal kept out of the findings).

::: llmsectest.probes.detectors
    options:
      members:
        - refusal_oracle
        - over_refusal_oracle
        - REFUSAL_MARKERS

## Scoring

CVSS v4.0 base scoring for OWASP categories. Each category carries a
representative `CVSS:4.0` base vector; the ten canonical scores ship baked into
the dependency-free core, with the optional `cvss` library used for arbitrary
vectors. Reported as the SARIF `security-severity` of each finding.

::: llmsectest.reporting.cvss
    options:
      members:
        - CVSSScore
        - score_vector
        - cvss_for_category
        - library_available
