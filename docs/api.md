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

Attack cases, target resolution, the runner, and application-mode scans.

::: llmsectest.probes
    options:
      members:
        - ProbeCase
        - ProbeOutcome
        - resolve_target
        - run_probe
        - app_cases
        - run_app_scan
        - cases_for
        - covered_categories
        - get_detector
        - register_detector
        - available_detectors
