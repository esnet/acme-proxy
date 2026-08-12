# Contribution Guidelines

We welcome all contributions but we ask you to do the following _before_ submitting a pull request:

- If it’s a **new feature request**, please open an issue with details about your proposed feature, what you want changed and why. What use cases would this feature solve and how will it benefit the community?

- For any **bug fixes**, please check if there are already open or closed issues about the topic and verify that you are testing with the latest version of acme-proxy.

- If you are **updating docs, improving tests**, please proceed directly to MR.

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
