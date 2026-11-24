# Roadmap and deliberate gaps

The repository is a portfolio, not a product. This page records what I would do
next and what I deliberately did not do.

## Next

1. **Capture real benign traffic.** Replace the generated benign corpus with a
   24-hour lab capture, reported separately from the generated set. The current
   1,000-event corpus is a statistical bound, not a field baseline.
2. **Run the purple team in CI.** The 2026-11-24 coverage run is a replay. An
   ephemeral lab in CI would make 8-step coverage and MTTD reproducible on every
   commit.
3. **Add host/auth telemetry.** Privilege Escalation is 0/2 because there is no
   host or authentication source. A Sysmon/auth-log collector would close it
   honestly.
4. **Build a pcap replay and backpressure test.** The current performance
   numbers are decoder and matcher microbenchmarks. The next step is a live
   sensor at sustained rate with a slow consumer and a full queue.
5. **Integrate the change calendar.** Replace the committed YAML with a read-only
   feed from the change-management system; the detection logic does not change.
6. **Add repo rules for the lab-only detections.** HMI login failure, C2 beacon
   and OT port scan are emitted by the lab but not scored by this repo.
7. **Add Wazuh as a conversion target.** It is the next platform in the
   deployment matrix.

## Deliberately not done

- **Coverage padding.** Tagging untested rules to raise 29/97 would destroy the
  repo's only real claim: every rule is validated.
- **Real malware.** The YARA family uses inert synthetic artifacts and the
  EICAR test string. Public-sample analysis in an isolated lab is the credible
  next step if that becomes the goal.
- **A live LLM provider.** The AI triage path is a tested stub; a live provider
  adds secrets and network without adding a detection-engineering signal.
- **A 24/7 SOC simulation.** There is no on-call rota, shift handover or
  production incident load; pretending otherwise would be dishonest.
- **A commercial BAS deployment.** AttackIQ is commercial; the lab uses a
  deterministic harness and an optional Caldera profile. AttackIQ Academy is
  training, not product experience.

## How to judge the repo

Read [`docs/CV_BULLETS.md`](CV_BULLETS.md) and [`docs/CLAIMS.md`](CLAIMS.md)
together. The bullets are what I would say in an interview; the claims register
is the evidence behind them. If a number is not in the claims register, do not
quote it.
