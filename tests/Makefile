
# Copyright (C) 2025 Web Server LLC

TENV=TEST_ANGIE_UNSAFE=1 \
     TEST_NGINX_UNSAFE=1 \
     TEST_ANGIE_LEAVE=onfail \
     ASAN_OPTIONS=detect_leaks=0 \
     TEST_ANGIE_GLOBALS="env ASAN_OPTIONS;" \
     TEST_ANGIE_JOBS=$(JOBS)

PROVE_OPTS=--shuffle \
          '--rules=seq=./acme_*.t' \
          '--rules=seq=./docker*.t' \
          '--rules=seq=./podman*.t' \
          '--rules=par=**'

REPORT=

ifeq ($(REPORT),yes)
TAP_FORMATTER_VERBOSITY=1
TENV+=TAP_FORMATTER_VERBOSITY=$(TAP_FORMATTER_VERBOSITY)
TENV+=PERL5LIB=lib
PROVE_OPTS+= --formatter Test::Formatter::JSON
endif

TENV_ADD=
PROVE_ADD_OPTS=

PROVE=prove

JOBS=1

ifneq ($(shell perl -e 'print($$<)'),0)
    # normal tests cannot be run as root
    TESTS=.
else
    # tests that require root privileges
    TESTS=proxy_bind_transparent.t \
          proxy_bind_transparent_capability.t \
          h3_bpf.t \
          http_resolver_conf.t
endif


RUNCMD=

test:
	@$(TENV) $(TENV_ADD) $(PROVE) \
            $(PROVE_OPTS) $(PROVE_ADD_OPTS) -j $(JOBS) $(TESTS)
	@echo "Tests run completed successfuly"


.PHONY:	test
