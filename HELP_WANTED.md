# Help wanted

AMES is open to contributions. Below is the hardening work that would make it stronger, roughly in order of impact. Pick anything, comment on (or open) an issue so others know you are on it, and see [CONTRIBUTING.md](CONTRIBUTING.md) to get started.

Found a vulnerability instead? Please report it privately, see [SECURITY.md](SECURITY.md).


### Move the vsock socket out of /tmp

**High impact.** `containment/backend.py` puts the guest to host event socket at `/tmp/ames-vsock-<run_id>.sock`. Another local user can pre-create that path, which can block the run or intercept the event channel. Use a private runtime directory (for example `$XDG_RUNTIME_DIR` with 0700) and update the conformance vectors if their hashes cover this field.

### Real Firecracker integration test

**Medium.** A CI job (or documented manual run) that boots a real microVM with the generated config and checks the containment properties end to end.

### Conformance vectors in a second language

**Medium.** Re-implement the vector checks outside Python so the spec, not the implementation, is what gets tested.
