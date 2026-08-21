---
name: A finding that isn't real
about: The scanner reported something that did not happen
title: "False finding: "
labels: false-positive
---

**Which category and which probe?**
<!-- e.g. LLM06 excessive agency, forged-authorization -->

**Why is it not real?**
<!-- e.g. the application only recited its own instructions, it never invoked anything -->

**The evidence from the report**
```
```

<!--
This is the report I take most seriously. The tool's whole argument is that a finding names a
reproducible attack rather than a risk score, so a finding that isn't real damages the thing the
project exists to be. Known limits are listed on each category's docs page, and if yours is one of
them I'd still like the case: a documented limit with a real example attached is how it gets fixed.
-->
