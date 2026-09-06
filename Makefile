# Zero-trust server verification targets.
#
# miri-test runs the crypto suite under the MIRI interpreter on nightly. Two
# deviations from a native test run are deliberate, and both are documented
# here because they are easy to mistake for weakened checking:
#
#   1. PROPTEST_CASES is lowered to 16 by default. MIRI interprets every
#      instruction, so the 100,000-case differential properties in crypto.rs
#      would take hours under interpretation. Sampling fewer cases trades
#      breadth for interpreter time; it does not weaken the memory-safety
#      and undefined-behavior guarantees MIRI makes about the cases it runs.
#
#   2. -Zmiri-disable-isolation lets the test process open /dev/urandom for
#      proptest's random seed. Isolation off permits real system calls; it
#      does not disable any part of the memory model or data race detection.
#
# Those are the only deviations. The default filter runs just the crypto
# module, the part of the codebase that must be provably free of undefined
# behavior; pass MIRI_TEST_FILTER=... to widen the run.

MIRI_TEST_FILTER ?= crypto
PROPTEST_CASES ?= 16

.PHONY: miri-test
miri-test:
	PROPTEST_CASES=$(PROPTEST_CASES) MIRIFLAGS="-Zmiri-disable-isolation" cargo +nightly miri test $(MIRI_TEST_FILTER)
