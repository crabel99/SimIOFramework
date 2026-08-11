# Issue tracker: Local Markdown

Issues and specs for this repo live as Markdown files in `.scratch/`.

## Conventions

- One feature per directory: `.scratch/<feature-slug>/`
- The spec is `.scratch/<feature-slug>/spec.md`
- Implementation issues are one file per ticket at `.scratch/<feature-slug>/issues/<NN>-<slug>.md`
- Triage state is recorded as a `Status:` line near the top of each issue file
- Comments and conversation history append under a `## Comments` heading

## Skill operations

- When a skill says to publish to the issue tracker, create a file under `.scratch/<feature-slug>/`.
- When a skill says to fetch a ticket, read the referenced file.
- A Wayfinder map is `.scratch/<effort>/map.md`, with child tickets under its `issues/` directory.
- Child tickets record `Type:`, `Status:`, and optional `Blocked by:` fields.
- Claim a ticket by setting `Status: claimed` before work.
- Resolve it by adding an `## Answer`, setting `Status: resolved`, and updating the map.
