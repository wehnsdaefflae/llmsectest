# LLM04 — Data and Model Poisoning

> Tampered training/fine-tuning data or a tampered model artifact introduces backdoors, bias or — most
> directly — code that runs when the model is loaded.

**Modality:** white-box (needs the model files). **Status:** covered.

OWASP lists data and model poisoning as LLM04. The training-data dimension is hard to test black-box, but
the most *direct* poisoning vector is concrete and checkable: the **serialized model artifact** a project
loads. Python's `pickle` — and every format built on it (`torch.save` `.pt`/`.pth`/`.ckpt`, `joblib`,
scikit-learn `.pkl`, numpy object arrays) — executes embedded callables when it is **loaded**. An attacker
who can swap or modify the weights file you download from a hub therefore gets arbitrary code execution the
moment you call `torch.load` / `pickle.load`: the classic "load a poisoned model, run the attacker's
payload" supply-side attack (the same risk ProtectAI `modelscan`, `picklescan`, `fickling` and Hugging
Face's hub-side pickle scanning address).

## How LLMSecTest tests it

Point LLMSecTest at the model file or directory with `--model-scan <path>`. It discovers serialized model
files (recursing through the tree, skipping vendored/virtualenv dirs) and walks each pickle's **opcode
stream** with the standard-library `pickletools` — it **never unpickles**, so scanning a hostile file is
itself safe. It flags any opcode that imports a code-execution primitive on load:

- **Code-execution import** (`critical`) — a `GLOBAL` / `STACK_GLOBAL` importing an OS/process/exec module
  (`os`, `posix`, `subprocess`, `socket`, `ctypes`, `runpy`, `pty`, …), a `builtins` execution primitive
  (`eval`, `exec`, `compile`, `__import__`, …), or a nested-unpickle primitive (`pickle.loads`,
  `numpy.load`, `torch.load`). These run OS/interpreter code, or unpickle further attacker bytes, on load.
- **Pickle gadget primitive** (`high`) — a reflection / partial-application gadget (`operator.attrgetter`,
  `functools.partial`/`reduce`, `importlib.import_module`) used to build pickle exploit chains. Lower
  severity because it needs chaining and is occasionally legitimate, but still surfaced.
- **Numpy object array** (`medium`) — a `.npy`/`.npz` whose dtype is `object`, so loading it requires
  `allow_pickle=True` and unpickles embedded objects; its trailing pickle is opcode-scanned too.

It understands raw pickle streams (protocols 0–5), PyTorch ≥1.6 **zip archives** (`.pt`/`.pth`/`.ckpt`,
whose `data.pkl` member is scanned) and `.npz`. The scan is **deterministic and offline** — no model load,
no network — so it is safe and reproducible in CI.

### Why it doesn't false-positive

The dangerous-import list is **curated and exact** (like LLM03's known-malicious-package list), not a fuzzy
heuristic. A legitimate weights file only references tensor-rebuild helpers — `torch._utils._rebuild_tensor_v2`,
`collections.OrderedDict`, `numpy.core.multiarray._reconstruct` — none of which is on the list, so a clean
model produces no finding. A model that imports `os.system` on load does not occur by accident.

```bash
llmsectest --model-scan models/                       # scan a directory of model files
llmsectest --model-scan model.pt                      # scan a single artifact
llmsectest --target app:http://localhost:8000/chat --model-scan models/   # app probes + model scan
```

Without `--model-scan`, LLM04 is reported as a **skipped** test (with the reason that it needs a model
path) — never a silent pass.

## Reading a finding

A finding names the technique, the model file (and the container member, for a zip), the evidence and a
concrete remediation — for example *"[code-execution import in serialized model] poisoned.pt!archive/data.pkl:
unpickling imports 'subprocess.Popen' …"*. In SARIF it maps to LLM04 and carries LLM04's CVSS v4.0 base
score (`7.1`) as its `security-severity`. Its **location points at the model file in the scanned project**,
not at LLMSecTest's own test file.

## Remediation

- Prefer a **code-free serialization format** — [safetensors](https://github.com/huggingface/safetensors)
  stores only tensors and runs no code on load.
- If you must load a pickle, use `torch.load(..., weights_only=True)` (or a restricted `Unpickler`) and load
  only artifacts whose **hash you have verified** from a trusted source.
- Treat a downloaded model like any other untrusted dependency: pin it, verify it, scan it in CI.

## Scope and roadmap

This is the offline, zero-dependency baseline, focused on the load-time code-execution vector. A richer
engine (ProtectAI `modelscan` / `picklescan` / `fickling`) behind an optional extra, and the training-data
provenance dimensions, are tracked follow-ups — mirroring how LLM03 layers the networked OSV.dev lookup on
top of its offline structural scan.

See the [OWASP LLM04 entry](https://genai.owasp.org/llmrisk/llm042025-data-and-model-poisoning/) for the
full guidance.
