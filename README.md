# momo-issue-tracker

Daily monitoring of newly opened issues in:

- `goharbor/harbor`
- `litmuschaos/litmus`
- `kubernetes-sigs/headlamp`
- `kubevirt/kubevirt`

Only issues opened by users named in each project's authoritative maintainer,
reviewer, or owner files are included. The exact 24-hour window is enforced
using `created_at`; issue updates do not affect inclusion.

## Daily digests

Digests are stored in [`digests/`](digests/) as `YYYY-MM-DD.md`.

The [daily workflow](.github/workflows/daily-digest.yml) runs at 10:00 AM IST
(04:30 UTC). It can also be started manually from the Actions tab.

## Trust policy

Commit volume alone does not establish trust. The allowlist is regenerated on
every run from project governance files, excludes emeritus sections, and
validates each login as a GitHub user before searching for issues.
