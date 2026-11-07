# ReleaseProof assertion

## Failure

Reviewers cite a passing scan for yesterday's build while promoting today's candidate.

## Mechanism

Digate seals scan outcomes to an exact digest and refuses promotion unless:

1. the signed verdict verifies under the trusted scanner key
2. the verdict digest equals the candidate digest being promoted
3. the registered release digest equals that same candidate digest

## Proof

A cryptographically valid signature issued for digest `D_old`, when presented against candidate digest `D_new`, leaves release state as `candidate`. Only a seal for `D_new` can move state to `promoted`.
