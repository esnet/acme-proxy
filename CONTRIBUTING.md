# Contribution Guidelines

We welcome all contributions but we ask you to do the following _before_ you submit a pull request:

- **New feature request** : please open an issue with details about your proposed feature, explain what you want changed and why. What use cases would this feature solve and how will it benefit the community? A discussion around implementation plan of your proposed feature with the project maintainers is needed for long-term supportability and security of the project.

- **Bug fixes** : please check if there are already open or closed issues about the topic and verify that you are testing with the latest version of acme-proxy. When opening a new issue please include details like - which version of acme-proxy you are using, contents of your `ca.json` file (without any credentials), any error logs, steps to replicate the bug. If you think you have found a fix, feel free to descibe the proposed fix as well.

- **Improvements around CI/Test Coverage** : Please proceed to submit PR.

- **Documentation fixes** : Please proceed to submit PR.

1. Fork the repo
2. In your fork, create a new branch for your work
3. Add code/fix in this branch, write tests, update the docs as necessary
4. Commit & push changes to your forked repo
5. Submit a pull request targeting our main branch

## Setup Development Environment

1. Install `go >= 1.25`
2. Install [pre-commit](https://pre-commit.com)
3. Clone the repo using `git clone --recurse-submodules git@github.com:esnet/acme-proxy.git`
4. Run `make dev`

## AI/LLM Usage Policy 🤖

Open source has always worked on a system of trust and verify.

Historically, the effort required to understand a codebase, implement a change, and submit that change for review was high enough that it naturally filtered out many low quality contributions from unqualified people. Unfortunately, the landscape has changed particularly with the advent of AI tools that allow people to trivially create plausible-looking but extremely low-quality contributions with little to no true understanding. Contributors can no longer be trusted based on the minimal barrier to entry to simply submit a change.

- Low effort drive by PRs will be closed without further engagement with the submitter.
- Any AI-generated code must be reviewed, tested, and integrated by human software developers to ensure quality and security.
- All PRs must be free of any copyrighted components.
- Project maintainers reserve the right to reject any PR that may introduce undue support overhead or compromise the project's long-term supportability.
