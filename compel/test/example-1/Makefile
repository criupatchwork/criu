CFLAGS			+= -O2
CFLAGS			+= -I ../../../compel/include/uapi
CFLAGS			+= -I ../../../compel/plugins/include/uapi
CFLAGS			+= -iquote ../../../include

ifeq ($(ARCH),)
        ARCH := x86
endif

compel_pack_lds		:= ../../../compel/arch/$(ARCH)/scripts/compel-pack.lds.S
ifneq ($(filter-out clean mrproper,$(MAKECMDGOALS)),)
CFLAGS_modifier-pie.o	:= $(shell ../../../compel/compel-host --arch=$(ARCH) cflags)
endif

clean:
	rm -f ./*.[od]
	rm -f ./donor
	rm -f ./modifier
	rm -f ./modifierpie-blob.h

%.o: %.c
	gcc -c $(CFLAGS) $(CFLAGS_$(@)) -o $@ $^

modifierpie.o: modifier-pie.o ../../../compel/plugins/std.built-in.o ../../../compel/plugins/fds.built-in.o
	ld -r -T $(compel_pack_lds) -o $@ $^

modifierpie-blob.h: modifierpie.o ../../../compel/compel-host
	../../../compel/compel-host hgen -f 	$<	\
                -l 4					\
                -v modifier_relocs			\
		-p modifier_blob_offset__		\
		-s modifier_blob			\
		-r modifier_nr_gotpcrel			\
		-u ../../../compel/include/uapi	        \
		-o $@

modifier.o: | modifierpie-blob.h

modifier: modifier.o log.o ../../../compel/libcompel.a
	gcc $(LDFLAGS) -o $@ $^

donor: donor.o log.o
	gcc $(LDFLAGS) -o $@ $^

all: donor modifier
	@true
.PHONY: all
