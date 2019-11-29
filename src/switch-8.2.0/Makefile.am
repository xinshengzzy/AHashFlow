ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

if WITH_TOFINO
EXTRA_TARGETS = targets
MAYBE_TOFINO = tofino
endif

if WITH_P4C_ALPHA
p4c_major := $(shell p4c --version | awk '{ print $2; }' | cut -f 1 -d '.')
# the p4c compiler defines these flags, however, we compile the control plane
# APIs with a native C compiler, and this tells it which compiler was used
# to compile the P4 program
AM_CPPFLAGS += -D__p4c__=1 -D__p4c_major__=$(p4c_major)
endif

if WITH_BMV2
MAYBE_BMV2 = bmv2
endif

if WITH_BMV2TOFINO
MAYBE_BMV2TOFINO = bmv2-tofino
endif

if WITH_SWITCHAPI
MAYBE_SWITCHAPI = switchapi
endif

if WITH_SWITCHSAI
MAYBE_SWITCHSAI = switchsai
endif

SUBDIRS = \
p4-build \
$(MAYBE_SWITCHAPI) $(MAYBE_SWITCHSAI) \
$(MAYBE_BMV2) \
$(MAYBE_BMV2TOFINO) \
$(MAYBE_TOFINO) $(EXTRA_TARGETS) \
doc
