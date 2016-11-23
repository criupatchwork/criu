ccflags-y		+= -I compel/include/uapi
ccflags-y		+= -I compel/plugins/include/uapi
ccflags-y		+= -iquote include

compel_pack_lds-native	:= compel/arch/$(ARCH)/scripts/compel-pack.lds.S

target			+= donor modifier modifierpie

donor-obj-y		+= donor.o
donor-obj-e		+= log.o

modifier-obj-y		+= modifier.o
modifier-obj-y		+= log.o

ifneq ($(filter-out clean mrproper,$(MAKECMDGOALS)),)
modifierpie-flags	:= $(shell $(compel_host) --arch=$(ARCH) cflags)
endif
modifierpie-obj-y	+= modifier-pie.o
modifierpie-obj-e	+= ./compel/plugins/std.built-in.o
modifierpie-obj-e	+= ./compel/plugins/fds.built-in.o

CFLAGS_modifier-pie.o	:= $(modifierpie-flags) $(ccflags-y)

$(obj)/donor.built-in.o: $(obj)/log.o

$(obj)/modifierpie.built-in.bin.o: $(obj)/modifierpie.built-in.o $(modifierpie-obj-e)
	$(call msg-gen, $@)
	$(Q) $(LD) -r -T $(compel_pack_lds-native) -o $@ $<

$(obj)/modifierpie-blob.h: $(obj)/modifierpie.built-in.bin.o $(compel_host)
	$(call msg-gen, $@)
	$(Q) $(compel_host) piegen -f 		$<	\
		-l 4					\
		-v modifier_relocs			\
		-p modifier_blob_offset__		\
		-s modifier_blob			\
		-r modifier_nr_gotpcrel			\
		-u $(SRC_DIR)/compel/include/uapi	\
		-o $@

$(obj)/modifier.d: $(obj)/modifierpie-blob.h
$(obj)/modifier.i: $(obj)/modifierpie-blob.h
$(obj)/modifier.o: $(obj)/modifierpie-blob.h

$(obj)/donor: $(obj)/donor.built-in.o
	$(call msg-link,$@)
	$(Q) $(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

$(obj)/modifier: $(obj)/modifier.built-in.o compel/libcompel.a
	$(call msg-link,$@)
	$(Q) $(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

all-y		+= $(obj)/donor $(obj)/modifier
cleanup-y	+= $(obj)/donor $(obj)/modifier
cleanup-y	+= $(obj)/modifierpie-blob.h
cleanup-y	+= $(obj)/modifierpie.built-in.bin.o
cleanup-y	+= $(obj)/pie.txt

run: $(obj)/donor $(obj)/modifier
	$(obj)/run.sh $(obj)/donor $(obj)/modifier $(obj)/pie.txt 2
.PHONY: run
