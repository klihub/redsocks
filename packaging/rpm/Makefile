THIS_DIR := $(shell pwd)
TOP_DIR  := $(shell \
    while [ ! -f README.md -a "$$(pwd)" != "/" ]; do \
      cd ..; \
    done; \
    pwd)

PACKAGING_DIR  := $(TOP_DIR)/packaging
SOURCES_DIR    := $(PACKAGING_DIR)/sources
SPEC_DIR       := $(PACKAGING_DIR)/rpm
BUILD_DIR      := $(TOP_DIR)/build
SPEC_FILE      := $(SPEC_DIR)/redsocks.spec

DISTRO_TYPE    := $(shell source /etc/os-release; echo $$ID)
DISTRO_VERSION := $(shell source /etc/os-release; echo $$VERSION_ID)
PACKAGES_DIR   := $(TOP_DIR)/packages/$(DISTRO_TYPE)/$(DISTRO_VERSION)
RPMS_DIR       := $(PACKAGES_DIR)/RPMS
SRPMS_DIR      := $(PACKAGES_DIR)/SRPMS

RPM_BUILD_OPT  := \
    --define '_specdir $(SPEC_DIR)' \
    --define '_sourcedir $(SOURCES_DIR)' \
    --define '_rpmdir $(RPMS_DIR)' \
    --define '_srcrpmdir $(SRPMS_DIR)' \
    --define '_builddir $(BUILD_DIR)/rpm/BUILD' \
    --define '_buildrootdir $(BUILD_DIR)/rpm/BUILDROOT'

RPM_PREPARE := mkdir -p $(BUILD_DIR)/rpm/{BUILD,BUILDROOT}
RPM_CLEANUP := rm -fr $(BUILD_DIR)/rpm/{BUILD,BUILDROOT}

GEN_GITVERSION := $(TOP_DIR)/.git-version
SED_VERSION    := sed -E 's/v([0-9]?.[0-9]*).*/\1/g'
SED_RELEASE    := sed -E 's/v[0-9]?.[0-9]*//g;s/-([0-9]*).*/\1/'
SED_PATCHES    := sed -E 's/v[0-9]?.[0-9]*-[0-9]//g;s/-([0-9]*)-g.*/\1/'
SED_SPEC_FILE  := sed "s/__VERSION__/$$SV/g;s/^Release: *.*/Release: $$SR/g"

GIT_VERSION    := $(shell \
    v=$$(git describe || git describe --tags || \
	   (echo v0.$$(date +%Y%m%d)-0-0-$$(git rev-parse HEAD | \
	     sed -E 's/(........).*/\1/'))); \
    [ -f $(GEN_GITVERSION) ] && cached=$$(cat $(GEN_GITVERSION)); \
    [ "$$cached" != "$$v" ] && echo $$v > $(GEN_GITVERSION); \
    echo $$v)

VERSION    := $(shell echo $(GIT_VERSION) | $(SED_VERSION))
RELEASE    := $(shell echo $(GIT_VERSION) | $(SED_RELEASE))
PATCHES    := $(shell echo $(GIT_VERSION) | $(SED_PATCHES))
RPMRELEASE := $(shell \
    echo $$(($$(cat $(SPEC_FILE).in | \
      grep ^Release: | sed 's/^Release: //' | \
        sed 's/__RELEASE__/$(RELEASE)/g;s/__PATCHES__/$(PATCHES)/g'))))


SPEC_REAL := $(shell realpath --relative-to=$(THIS_DIR) $(SPEC_FILE))
TARBALL   := $(SOURCES_DIR)/v$(VERSION)-$(RPMRELEASE).tar
TARBAGZ   := $(TARBALL).gz

# Pass V=1 to $(MAKE) to disable silent/suppressed operation.
ifeq ($(strip $(V)),1)
    Q :=
else
    Q := @
endif

# By default we build rpms.
all: rpms


#
# Rule to build binary and source RPMS.
#

rpm rpms: $(SPEC_FILE) $(TARBAGZ)
	$(Q)$(RPM_PREPARE) && \
	    rpmbuild $(RPM_BUILD_OPT) -bb $(SPEC_FILE) && \
	    rpmbuild $(RPM_BUILD_OPT) -bs $(SPEC_FILE) && \
	$(RPM_CLEANUP)

#
# Rules to generate spec file and roll tarballs.
#

$(SPEC_FILE) S(SPEC_REAL): $(SPEC_FILE).in $(GEN_GITVERSION)
	$(Q)SV=$(VERSION); SR=$(RPMRELEASE); \
	cat $< | $(SED_SPEC_FILE) > $@

$(TARBAGZ): $(GEN_GITVERSION)
	$(Q)rm -f $@ $(TARBAGZ) $(TARBALL); \
	(cd $(TOP_DIR); \
	   git archive --prefix=redsocks-$(VERSION)-$(RPMRELEASE)/ \
	     -o $(TARBALL) HEAD) && \
	gzip -9 $(TARBALL) && \
	echo "Generated $$(realpath --relative-to=$$(pwd) $(TARBAGZ))."

spec: $(SPEC_FILE)

tarball: $(TARBAGZ)


#
# debug rule to dump variables
#

show:
	$(Q)echo "$(VAR)=$($(VAR))"
