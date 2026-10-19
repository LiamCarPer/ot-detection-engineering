## Summary

<!-- What does this change, and why? -->

## Threat-model impact

<!-- Which threat (T-xxx) or control (C-xxx) does this add, change or invalidate?
     If none, say why. Updating metadata/threat-model.yaml or
     metadata/security-controls.yaml is part of the change when it applies. -->

## Security checklist

- [ ] `make security-preflight` passes (governance, action pins, coverage).
- [ ] New input has a trust level and a size/shape limit.
- [ ] No secret, token or key is added to code, fixtures or workflows.
- [ ] New dependencies are pinned and necessary.
- [ ] Actions added to a workflow are pinned by commit SHA.
- [ ] Generated artifacts (`deploy/`) and evidence are regenerated.
- [ ] A security regression test accompanies a fixed defect.
- [ ] If this touches the triage path: output is schema-validated, never
      executed, has no tool access, and requires human review.

## Verification

<!-- Commands run and their result. -->
