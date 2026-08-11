# Domain Docs

How engineering skills consume this repository's domain documentation.

## Before exploring

- Read root `CONTEXT.md` when it exists.
- If root `CONTEXT-MAP.md` exists, read each linked context relevant to the work.
- Read applicable decisions under `docs/adr/`.

If these files do not exist, proceed silently. The domain-modeling workflow creates them lazily
when terminology or architectural decisions are resolved.

## Layout

This is a single-context repository:

```text
/
├── CONTEXT.md
├── docs/adr/
└── cores/
```

Use terminology defined by `CONTEXT.md`. If proposed work contradicts an ADR, identify the conflict
explicitly rather than silently overriding the decision.
