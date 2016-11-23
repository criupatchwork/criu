compel_host	:= compel/compel-host
export compel_host

compel/test/example-1/%:
	$(Q) $(MAKE) $(build)=compel/test/example-1 $@
compel/test/example-1:
	$(Q) $(MAKE) $(build)=compel/test/example-1 all
.PHONY: compel/test/example-1
all-y	+= compel/test/example-1

test-run-example-1: compel/test/example-1
	$(E) "  RUN     " $@
	$(Q) $(MAKE) $(build)=compel/test/example-1 run
.PHONY: test-run-example-1

test-run: test-run-example-1
	@true
.PHONY: test-run

clean-examples:
	$(Q) $(MAKE) $(build)=compel/test/example-1 clean
.PHONY: clean-examples
