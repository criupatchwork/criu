target		+= parasite restorer

compel_lds	:= $(SRC_DIR)/compel/arch/$(ARCH)/scripts/compel-pack.lds.S
compel_std	:= $(SRC_DIR)/compel/plugins/std.built-in.o
parasite-obj-e	+= ./compel/plugins/std.built-in.o
restorer-obj-e	+= ./compel/plugins/std.built-in.o

parasite-obj-y	+= parasite.o
restorer-obj-y	+= restorer.o
restorer-obj-y	+= ./$(ARCH_DIR)/restorer.o

ifeq ($(ARCH),x86)
        ifeq ($(CONFIG_COMPAT),y)
                restorer-obj-y	+= ./$(ARCH_DIR)/call32.o
                restorer-obj-y	+= ./$(ARCH_DIR)/sigaction_compat_pie.o
        endif
endif

#
# We can't provide proper mount implementation
# in parasite code -- it requires run-time rellocation
# applications, which is not the target of the
# project.
#
CFLAGS		:= $(filter-out -pg $(CFLAGS-GCOV),$(CFLAGS))
CFLAGS		+= -iquote $(SRC_DIR)/criu/arch/$(ARCH)/include
CFLAGS		+= -iquote $(SRC_DIR)/criu/include
CFLAGS		+= -iquote $(SRC_DIR)/include
CFLAGS		+= -iquote $(SRC_DIR)

ccflags-y	+= -I compel/include/uapi
ccflags-y	+= -I compel/plugins/include/uapi
ccflags-y	+= -DCR_NOGLIBC
ccflags-y	+= -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0

ifneq ($(filter-out clean mrproper,$(MAKECMDGOALS)),)
        CFLAGS	+= $(shell $(SRC_DIR)/compel/compel-host --arch=$(ARCH) cflags)
endif

ifeq ($(SRCARCH),arm)
        ccflags-y	+= -marm
endif

asflags-y	+= -D__ASSEMBLY__

GEN-OFFSETS	:= $(obj)/../../scripts/gen-offsets.sh

BLOBS		+= $(obj)/restorer-blob.h $(obj)/parasite-blob.h

.SECONDARY:

target-name = $(patsubst criu/pie/%-blob.h,%,$(1))

ifeq ($(piegen-y),y)
ifeq ($(strip $(V)),)
        piegen_stdout := >/dev/null
endif

$(obj)/restorer.built-in.o: $(compel_std)
$(obj)/parasite.built-in.o: $(compel_std)
$(obj)/%.built-in.bin.o: $(obj)/%.built-in.o $(obj)/pie.lib.a $(compel_lds)
	$(call msg-gen, $@)
	$(Q) $(LD) -r -T $(compel_lds) -o $@ $< $(obj)/pie.lib.a

$(obj)/%-blob.h: $(obj)/%.built-in.bin.o $(SRC_DIR)/compel/compel-host
	$(call msg-gen, $@)
	$(Q) $(SRC_DIR)/compel/compel-host hgen -f $<			\
		-l 4							\
		-v $(call target-name,$@)_relocs			\
		-p $(call target-name,$@)_blob_offset__			\
		-s $(call target-name,$@)_blob				\
		-r $(call target-name,$@)_nr_gotpcrel			\
		-u $(SRC_DIR)/compel/include/uapi			\
		-o $@ $(piegen_stdout)

else # !piegen-y

# ld on arm doesn't like -pie and -r options together
ifeq ($(filter arm aarch64,$(ARCH)),)
        LD_R := -r
endif

$(obj)/restorer.built-in.o: $(compel_std)
$(obj)/parasite.built-in.o: $(compel_std)
$(obj)/%.built-in.bin.o: $(obj)/%.built-in.o $(compel_lds) $(obj)/pie.lib.a
	$(call msg-gen, $@)
	$(Q) $(LD) $(LD_R) -T $(compel_lds) -o $@ $< $(obj)/pie.lib.a

$(obj)/%.built-in.bin: $(obj)/%.built-in.bin.o
	$(call msg-gen, $@)
	$(Q) $(OBJCOPY) -O binary $^ $@

$(obj)/%-blob.h: $(obj)/%.built-in.bin $(GEN-OFFSETS)
	$(call msg-gen, $@)
	$(Q) $(SH) $(GEN-OFFSETS) $(@:-blob.h=) $(call target-name,$@) $(CROSS_COMPILE) > $@

endif # !piegen-y

all-y += $(BLOBS)
# blobs and pields are in cleanup, rather than in mrproper because
# we want them to be re-generated after `make clean && make`
cleanup-y += $(BLOBS)
cleanup-y += $(obj)/*.bin
cleanup-y += $(obj)/*.built-in.bin.o
cleanup-y += $(obj)/*.built-in.bin
