# Contributing Guidelines

For anyone looking to get involved to this project, we are glad to hear from you. Here are a few types of contributions
that we would be interested in hearing about.

- Bug fixes
    - If you find a bug, please first report it using GitHub Issues.
- New Features
    - If you'd like to accomplish something in the plugin that it doesn't already do, describe the problem in a new
      GitHub Issue.
    - If you'd like to implement the new feature, please wait for feedback from the project maintainers before spending
      too much time writing the code. In some cases, `enhancement`s may not align well with the project objectives at
      the time.
- Tests, Documentation, Miscellaneous
    - If you think the test coverage could be improved, the documentation could be clearer, you've got an alternative
      implementation of something that may have more advantages, or any other change we would still be glad hear about
      it.

#### Requirements

For a contribution to be accepted:

- The test suite must be complete and pass
- Code must follow existing styling conventions
- Commit messages must be descriptive. Related issues should be mentioned by number.

If the contribution doesn't meet these criteria, a maintainer will discuss it with you on the Issue. You can still
continue to add more commits to the branch you have sent the Pull Request from.

Don't forget to give the project a star ⭐!

### How to Contribute

1. Fork this repository
2. Create your Feature Branch (`git checkout -b feature/new_feature`)
3. Commit your Changes (`git commit -m 'Implement new_feature, ...'`)
4. Push to the Branch (`git push origin feature/new_feature`)
5. Open a Pull Request

### Commits

We use conventional commits to ensure consistent commit messages:

- `feat:` New features
- `fix:` Bug fixes
- `docs:` Documentation changes
- `ci:` Maintenance tasks
- `refactor:` Code changes that neither fix bugs nor add features

Example: `fix(scan): fix a typo`

You can read more about Conventional Commits [here](https://www.conventionalcommits.org/en/v1.0.0/).

### Local Development Guide

Thanks for your interest in contributing! Below are the steps to build, lint, test, and verify the project locally.

Check also the [Developer Notes](docs/pgrwl/developer-notes.md) for additional information and guidelines.

Debug with your favorite editor and a local PostgreSQL container ([local-dev-infra](test/integration/environ/)).

```bash
# Compile the project
make build

# Run linter (should pass without errors)
# Requires golangci-lint to be installed
make lint

# Run all fast unit tests. They should pass before submitting a PR.
make test

# Run integration tests (slow, but critical)
# Requires Docker and Docker Compose to be installed
make test-integ-scripts

# Parallel integration tests (NOTE: ~20 containers)
make test-integ-par-17
make test-integ-par-18

# This builds the release artifacts using GoReleaser in snapshot mode (nothing is published).
# Requires goreleaser to be installed
make snapshot
```
