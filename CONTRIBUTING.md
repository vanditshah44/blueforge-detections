# Contributing a detection

Detections are treated as code. To add or change a rule:

1. **Branch** from `main`.
2. **Write the rule** as Sigma under the correct `rules/<platform>/<category>/`
   directory. Follow the house policy (enforced by CI):
   - stable, unique UUID `id` (generate with `python -c "import uuid;print(uuid.uuid4())"`)
   - at least one `attack.tXXXX` technique tag
   - a `description`, `references`, `author`, `date`
   - an explicit `level` and a documented `falsepositives` section
3. **Validate locally** before opening a PR:
   ```bash
   make lint      # sigma check
   make test      # policy tests
   make convert   # must compile to SPL + KQL
   ```
4. **Document** the emulation you used to validate the rule (Atomic Red Team
   test ID, command, or manual steps) in the PR description, plus any tuning you
   applied to reduce false positives.
5. **Open a pull request.** CI must be green — a rule that fails lint, tests, or
   cross-SIEM compilation will not merge.

## Rule style
- One behaviour per rule; prefer sub-technique-level precision.
- Name selections descriptively (`selection_img`, `selection_enc`) and keep the
  `condition` readable.
- Favour high-signal fields; document expected benign sources rather than
  silently narrowing until the rule never fires.
