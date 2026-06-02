# Model Supply Chain

Loading a model, its code, or its weights from an untrusted or unverified source. The high-impact cases run code at load time: executing code shipped with a third-party model, or deserializing weights through pickle. Pin and verify artifacts, and do not enable remote code execution for a model you do not control.

Bring this skill into scope when you see:
- from_pretrained or a model or dataset download call
- trust_remote_code set on a model load
- torch.load, pickle.load, or joblib.load of model weights

## Dimensions to rule on

Output one verdict per dimension below (SECURE, VULNERABLE, PARTIAL, NOT_PRESENT, or UNKNOWN), even when the code is fine, so the report records what was checked. Use the dimension name as the verdict's `dimension`.

### remote code

Secure patterns (support a SECURE verdict):
- Load a model with remote code execution off and a pinned revision. Why it is safe: The third-party repo cannot run code at load time and the artifact is pinned. Look for: `trust_remote_code=False`, `revision=`.

Insecure patterns (support a VULNERABLE verdict):
- [CRITICAL CWE-494] Load a model with trust_remote_code=True, which executes code shipped in the model repository at load time. Why it is a problem: A malicious or compromised model repo runs arbitrary code in your process. Look for: `trust_remote_code=True`, `from_pretrained`.

  Example of the bug:

  ```python
  model = AutoModel.from_pretrained("vendor/model", trust_remote_code=True)
  ```

  Fixed:

  ```python
  model = AutoModel.from_pretrained("vendor/model", revision="a1b2c3d")
  ```

### artifact integrity

Secure patterns (support a SECURE verdict):
- Load weights from a data-only format such as safetensors. Why it is safe: A data-only weights format cannot execute code on load. Look for: `safetensors`, `load_file`.

Insecure patterns (support a VULNERABLE verdict):
- [HIGH CWE-502] Deserialize model weights or a checkpoint through pickle, for example torch.load or joblib.load on a downloaded file, which can run code on load. Why it is a problem: Pickle-based loaders execute code embedded in the file during deserialization. Look for: `torch.load`, `pickle.load`, `joblib.load`.

  Example of the bug:

  ```python
  state = torch.load(downloaded_checkpoint)
  ```

  Fixed:

  ```python
  from safetensors.torch import load_file
  state = load_file("model.safetensors")
  ```

## Judgement notes

- Cite an evidence file and line for every VULNERABLE or PARTIAL verdict; a problem with no location is not reportable.
