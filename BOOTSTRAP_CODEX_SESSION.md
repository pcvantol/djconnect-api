# DJConnect Repository Bootstrap

Status: repository-local clean-session entrypoint

Repository: `pcvantol/djconnect-api`

## Purpose

This is the small repository-specific bootstrap for clean Codex or AI-agent
sessions in this repository. It references the canonical DJConnect Platform
Foundation instead of duplicating it.

## Required Startup Flow

A clean session must:

1. Read this document.
2. Read `AGENTS.md`.
3. Read `CANONICAL_REFERENCES.md`.
4. Read `REPOSITORY_STATUS.md`.
5. Read `PROMPT_INDEX.md` when the work is phase-driven.
6. Read canonical platform documents in `pcvantol/djconnect` only as needed for
   the current task.
7. Read repository-local implementation, build, release or test docs relevant
   to the task.
8. Return a readiness summary.
9. Wait for the next implementation prompt unless the user has already supplied
   one.

## Repository Role

central API trust/relay boundary, APNs relay, per-install token bootstrap and future entitlement/profile-cloud surfaces.

## Ownership Boundary

This repository owns central API implementation, Cloudflare Worker runtime, APNs relay, per-install token bootstrap and API-owned localized display-message mapping.

This repository does not own local-first Community runtime behavior, Home Assistant integration implementation, native client UX or canonical foundation docs.

## Canonical References

Use `CANONICAL_REFERENCES.md` for the local map of canonical platform,
verification, Meta Engineering, prompt and ownership references.

## Prompt Discovery

Use `PROMPT_INDEX.md` for repository-local phase state only. This repository
must not copy the full platform roadmap from `pcvantol/djconnect`.

## Completion Protocol

For engineering phases, follow the completion protocol in
`pcvantol/djconnect/docs/meta/PHASE_COMPLETION_PROTOCOL.md` and record durable
repository knowledge in the correct local or canonical document.

## Stop Condition

After bootstrap, stop with a readiness summary unless the user has provided an
explicit implementation, documentation, release or verification prompt.
