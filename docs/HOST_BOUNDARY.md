# Host Boundary

This repository must never turn the maintainer's computer into infrastructure for other users.

Default architecture:

```text
User's machine
  |
  +-- local copy of this repository
  +-- local data
  +-- local model/service when applicable

Maintainer's machine
  |
  +-- NOT a backend
  +-- NOT a public server
  +-- NOT a relay
  +-- NOT a self-hosted runner
  +-- NOT remotely reachable by repository users
```

If a user chooses to deploy a network service, that deployment belongs to that user and must be explicitly configured on infrastructure they control.

Security invariant: cloning or using this repository must not create a network path into the maintainer's machine.
