local:
	./travis-tests
.PHONY: local

after_success:
	./travis-after_success
.PHONY: after_success

target-suffix =
ifdef CLANG
	target-suffix = -clang
endif

TARGETS := alpine fedora-rawhide centos phaul
ZDTM_OPTIONS :=

alpine: ZDTM_OPTIONS=-x zdtm/static/binfmt_misc -x zdtm/static/netns-nf -x zdtm/static/sched_policy00 -x zdtm/static/seccomp_strict -x zdtm/static/sigaltstack -x zdtm/static/signalfd00 -x zdtm/static/config_inotify_irmap

$(TARGETS):
	echo 'DOCKER_OPTS="--storage-driver=devicemapper"' > /etc/default/docker
	restart docker
	$(MAKE) -C ../build $@$(target-suffix)
	docker run --env-file docker.env --rm -it --privileged -v /lib/modules:/lib/modules --tmpfs /run criu-$@ scripts/travis/travis-tests

fedora-asan:
	echo 'DOCKER_OPTS="--storage-driver=devicemapper"' > /etc/default/docker
	restart docker
	$(MAKE) -C ../build $@$(target-suffix)
	docker run --rm -it --privileged -v /lib/modules:/lib/modules --tmpfs /run criu-$@ ./scripts/travis/asan.sh $(ZDTM_OPTIONS)

phaul-test:
	echo 'DOCKER_OPTS="--storage-driver=devicemapper"' > /etc/default/docker
	restart docker
	$(MAKE) -C ../build alpine
	docker run --rm -it --privileged -v /lib/modules:/lib/modules --tmpfs /run criu-alpine ./scripts/travis/phaul

docker-test:
	./docker-test.sh

runc-test:
	SKIP_TRAVIS_TEST=1 ./travis-tests
	# clone runc we actually just want the test suite
	git clone https://github.com/opencontainers/runc
	# download the released binary
	curl -o runc/runc -sSL https://github.com/opencontainers/runc/releases/download/v1.0.0-rc5/runc.amd64
	chmod 755 runc/runc
	# for the test suite we need to build recvtty
	docker build -t runc -f Dockerfile.runc .
	docker run runc tar c -C contrib/cmd/recvtty recvtty | tar x -C runc/contrib/cmd/recvtty
	# install current criu
	install -D -m0755 ../../criu/criu /usr/local/sbin/criu
	# get bats to run tests
	git clone https://github.com/sstephenson/bats.git
	cd bats && git reset --hard 03608115df2071fff4eaaff1605768c275e5f81f
	cd bats && ./install.sh /usr/local
	# the runc test suite does 'go env GOARCH' to detect the arch, let's fake this
	echo '#!/bin/bash\necho travis\n' > /usr/local/bin/go
	chmod 755 /usr/local/bin/go
	cd runc && bats -t tests/integration/checkpoint.bats

%:
	$(MAKE) -C ../build $@$(target-suffix)
