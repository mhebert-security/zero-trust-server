# modbus-dnp3-traffic-analysis

The write that can stop a line. Modbus and DNP3 still move control traffic
in the clear, built for a time when the network was a locked room, and this
project builds a baseline of normal traffic on those links so the message
that does not belong shows up while it is still a packet.

## what it is

A detection project for OT and ICS links that starts from the physics of the
place instead of a list of known attack names. A link that polls a handful
of unit identifiers on a fixed cadence has a shape. The anomaly is anything
that does not fit that shape: a new unit, an unscheduled write, a function
code that never appears in the baseline.

The repo is the plan and the scaffold. The first artifact is a reproducible
lab baseline, and it is not written yet. There are no captures and no
detection rules in the tree on purpose, because a baseline that cannot be
rebuilt is a story, not evidence.

## why the method

Neither Modbus nor DNP3 authenticates or encrypts by default. A single
write to the wrong coil can stop a physical line, so the traffic that
reaches a controller deserves the same scrutiny as the traffic that reaches
a database. The baseline exists to make the difference between normal and
alarming concrete instead of intuitive.

A write that changes a setpoint is normal at shift change and alarming at
3 a.m. on a Sunday. That distinction is the whole problem. A detection that
cannot state what normal looks like will shout at everything and mean
nothing.

## the phases

The plan runs in four phases, tracked in the repo with nothing marked done
on intent. First, stand up a reproducible Modbus and DNP3 lab and capture
normal traffic with a script. Second, write the baseline down as concrete
expectations. Third, detect and document anomalies against that baseline,
one scenario at a time. Fourth, let the findings feed the OT and ICS CVE
research roadmap.

The lab is pymodbus for Modbus and the usual open source outstation and
master pair for DNP3, all on loopback, with tshark recording a defined run.
When a clean machine can reproduce that run from the repo alone, the
baseline work can start.

## status

Priority 3 in the security plan, and the highest long-term strategic value
of the four projects here. It is the least built. The statement and the
plan are written, the lab is not, and that order is deliberate: the writeup
you are reading and the repo it describes agree about what exists.

## links

The repository is
[github.com/mhebert-security/modbus-dnp3-traffic-analysis](https://github.com/mhebert-security/modbus-dnp3-traffic-analysis).
The plan lives in its docs directory, and every phase flips to done only
when the artifact that proves it lands in the tree.
