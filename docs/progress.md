# Implementation progress

Running status of the implementation, updated in every pull request. **Production readiness is not claimed until every feature in [plan.md](plan.md) is implemented and its quality gate passes.** This file says exactly what is done, what is verified and how, and what is not.

## Milestones

| # | Milestone | Status | PR |
|---|---|---|---|
| M0 | Foundations: solution, shared contracts, package-free guard, CI | in review | feat/p0-foundations |

## Verified so far

- `dotnet build EggMail.slnx` and `dotnet test EggMail.slnx` pass locally (Core address/id tests, architecture guard tests).
- The package-free guard checks `.csproj` files and `obj/project.assets.json` of the guarded assemblies.

## Not verified / known gaps

- **GitHub Actions is disabled for the repository by the organization**, so the CI workflow and the release workflow cannot run. Pull requests are merged after a full local `dotnet test` and two self-review passes; the workflows are written but unproven on GitHub. Owner action: allow Actions for `eggspot/EggMail` ([open-questions.md](open-questions.md)).
- Everything beyond the skeleton is not implemented yet. See the milestone table.
- Docker image build and GHCR publish can only run in GitHub Actions (no Docker is used locally).
- No real-internet MX delivery has been tested; no independent security audit has been done.
