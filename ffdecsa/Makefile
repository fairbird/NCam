CC = $(CROSS)gcc
STRIP = $(CROSS)strip

# Compiler warnings
FFDECSA_WARN = -W -Wall # -Wold-style-definition -Wmissing-prototypes

# Compiler errors
FFDECSA_ERROR = -Werror=uninitialized

# Compiler optimizations
FFDECSA_OPTS = -O3 -funroll-loops -fomit-frame-pointer -fno-schedule-insns
TARGETHELP := $(shell $(CC) --target-help 2>&1)
ifneq (,$(findstring sse2,$(TARGETHELP)))
FFDECSA_OPTS += -fexpensive-optimizations -mmmx -msse -msse2 -msse3 # Fixme: for avx... (-mavx2 or -mavx512bw)
else ifneq (,$(findstring neon,$(TARGETHELP)))
FFDECSA_OPTS += -fexpensive-optimizations -mfpu=neon
else
FFDECSA_OPTS += -fexpensive-optimizations
endif

# Setup quiet build
Q =
SAY = @true
ifndef V
Q = @
SAY = @echo
endif

ifdef PARALLEL_MODE
override CFLAGS += -DPARALLEL_MODE=$(PARALLEL_MODE)
endif

all: ffdecsa-test

-include $(subst .o,.d,ffdecsa.o)

ffdecsa.o: ffdecsa.c
	@$(CC) -MP -MM -MT $@ -o $(subst .o,.d,$@) $<
	$(SAY) "CC	$<"
	$(Q)$(CC) $(FFDECSA_WARN) $(FFDECSA_ERROR) $(CFLAGS) $(FFDECSA_OPTS) -c $< -o $@

ffdecsa-test: ffdecsa.o
	$(Q)$(CC) $(CFLAGS) ffdecsa.o ffdecsa_test.c -o $@
	$(SAY) "STRIP	$@"
	$(Q)$(STRIP) ffdecsa-test

clean:
	$(Q)rm -rf ffdecsa.o ffdecsa.d

distclean: clean
	$(Q)rm -rf ffdecsa-test

help:
	@-printf "\
   make V=1        - Enable verbose build\n\
\n\
 Build variables:\n\
   CROSS=prefix   - Set tools prefix. For example if you want to cross compile\n\
                    for ARM architecture you can run: 'make CROSS=arch-platform-'\n\
                    If you don't have the directory where cross compilers are\n\
                    in your PATH you can run:\n\
                    'make CROSS=/my-toolchain/bin/arch-platform-'\n\
\n\
   FFDECSA_WARN=  - This variable holds compiler warning parameters.\n\
                    Default FFDECSA_WARN value is:\n\
                    '$(FFDECSA_WARN)'\n\
                    To change the text, set this variable to FFDECSA_WARN=text.\n\
\n\
   FFDECSA_ERROR= - This variable holds compiler error parameters.\n\
                    Default FFDECSA_ERROR value is:\n\
                    '$(FFDECSA_ERROR)'\n\
                    To change the text, set this variable to FFDECSA_ERROR=text.\n\
\n\
   FFDECSA_OPTS=  - This variable holds compiler optimization parameters.\n\
                    Default FFDECSA_OPTS value is:\n\
                    '$(FFDECSA_OPTS)'\n\
                    To change the text, set this variable to FFDECSA_OPTS=text.\n\
\n\
   Parallel mode  - Parallelization stuff, large speed differences are possible.\n\
                    Possible choices:\n\
                    'PARALLEL_32_4CHAR'\n\
                    'PARALLEL_32_4CHARA'\n\
                    'PARALLEL_32_INT'\n\
                    'PARALLEL_64_8CHAR'\n\
                    'PARALLEL_64_8CHARA'\n\
                    'PARALLEL_64_2INT'\n\
                    'PARALLEL_64_LONG'\n\
                    'PARALLEL_64_MMX'\n\
                    'PARALLEL_128_16CHAR'\n\
                    'PARALLEL_128_16CHARA'\n\
                    'PARALLEL_128_4INT'\n\
                    'PARALLEL_128_2LONG'\n\
                    'PARALLEL_128_2MMX'\n\
                    'PARALLEL_128_SSE'\n\
                    'PARALLEL_128_SSE2'\n\
                    'PARALLEL_256_AVX2'\n\
                    'PARALLEL_512_AVX512'\n\
                    For example, if you want.\n\
                    'make PARALLEL_MODE=PARALLEL_32_INT'\n\
                    or \n\
                    'make CFLAGS="\"-DPARALLEL_MODE=PARALLEL_32_INT"\"'\n\
\n\
   FFDECSA_TEST=1 - Builds 'ffdecsa-test' binary\n\
\n\
 Cleaning targets:\n\
   clean          - Remove FFdecsa compiled object files.\n\
   distclean      - Executes clean target and also removes binary files.\n"

.PHONY: all clean distclean help ffdecsa.o
