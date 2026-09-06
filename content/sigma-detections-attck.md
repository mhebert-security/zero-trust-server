# sigma-detections-attck

A detection rule is only as trustworthy as the framework that names what it
caught. Every rule in this repo maps to a MITRE ATT&CK technique, so a hit
answers which stage of an intrusion it belongs to, and the rule is written
against a reproducible test before it is called done.

## what it is

Sigma is a common language for detections: one rule, written once, that
translates to the query language of whatever stack is watching. This repo
keeps the rules next to the evidence that earns each one a home. The layout
separates the rule from its Wazuh translation, its test evidence, and the
coverage matrix that shows what is actually covered, so nothing ships as a
rule and a promise.

## why the technique name matters

A detection that says "this looks bad" gives an analyst a job, not an
answer. Naming the technique, T1059.001 for command and scripting
interpreter, tells the analyst which stage of an intrusion this belongs to
and what the next move probably is. The technique name is the thread that
ties one alert to the story around it.

## the first rule

The repo opens with one experimental rule: PowerShell invoked with the
encoded command flag, which lets an attacker hide payload content from
command line inspection. The detection looks for powershell.exe or pwsh.exe
with an encoded command variant on the command line, and it maps to
T1059.001.

```yaml
detection:
  selection_image:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
  selection_flags:
    CommandLine|contains:
      - ' -EncodedCommand '
      - ' -EnC '
      - ' -EC '
  condition: selection_image and selection_flags
```

The rule is honest about what it will not catch and what it will shout
about. Encoded PowerShell is rare where legitimate automation does not use
it, and common where deployment tooling runs, so the false positive list
names both sides before the rule ships.

## how a rule earns a home

A rule leaves the experimental pile only when it passes the gates written in
the contributing guide: a stated sample, a recorded match against telemetry,
and the false positives it accepts. A template makes the next rule start
from the same shape, and a lint workflow checks every submission against the
Sigma schema.

## status

Started, and labeled that way. The first rule is written and linted, its
Wazuh translation is in place, and the evidence file names the lab and the
Atomic Red Team test that will validate it. That run is pending. When it
passes, the rule moves off experimental and the coverage matrix grows by one.

## links

The repository is
[github.com/mhebert-security/sigma-detections-attck](https://github.com/mhebert-security/sigma-detections-attck),
and its contributing guide names the gates a rule must pass to leave the
experimental pile.
