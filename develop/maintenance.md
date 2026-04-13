+++
title = 'Maintenance'
weight = 40
BookToC = true
+++

# Guide to patching upstream related changes

- While smallstep/certifiates is meant to serve as the upstream Go module for acme-proxy, we have to maintain some patches/fixes ourselves until they get merged upstream. Our patched version of step-ca is currently maintained in a forked repo [esnet/certificates](https://github.com/esnet/certificates).

- The branch naming scheme for our patches follow a pattern `patch/upstream-version`. For example: patches made against smallstep/certificates `v0.30.2` are in a branch called `patch/v0.30.2`.

- Once the patches have been applied and tested, we tag the commit using a naming scheme `[upstream version]-patch.count`. So if the patches have been applied against upstream `v0.30.2` our go.mod in acme-proxy should contain

```
replace github.com/smallstep/certificates => github.com/esnet/certificates v0.30.2-patch.2
```

Where the trailing patch.2 indicates _total count of patches applied_ so far i.e two. Should we encounter another another bug in upstream v0.30.2 & have to maintain a third patch then we add our fix to github.com/esnet/certificates under branch patch/v0.30.2, test it & create a commit tag with v0.30.2-patch.3.

```
git tag -a v0.30.2-patch.3 -m "detailed commit message"
git push --tags v0.30.2-patch.3
```

- Update the go.mod in acme-proxy repo to point to the new tag

```
replace github.com/smallstep/certificates => github.com/esnet/certificates v0.30.2-patch.3
```

As a best practice, use [atomic commits for each patch](https://github.com/smallstep/certificates/compare/master...esnet:certificates:patch/v0.30.2) with detailed commit message.
