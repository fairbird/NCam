#---------------------------------------------------------------------
project (ffdecsa)
#----------------------- compile options -----------------------------
if (NOT FFDECSA_WARN)
	set(FFDECSA_WARN "-W -Wall")
endif (NOT FFDECSA_WARN)

if (NOT FFDECSA_ERROR)
	set(FFDECSA_ERROR "-Werror=uninitialized")
endif (NOT FFDECSA_ERROR)

if (NOT FFDECSA_OPTS)
	set(FFDECSA_OPTS "-O3 -funroll-loops -fomit-frame-pointer -fno-schedule-insns")
	if (CMAKE_SYSTEM_PROCESSOR MATCHES "(x86)|(X86)|(amd64)|(AMD64)")
		set(FFDECSA_OPTS "${FFDECSA_OPTS} -msse -msse2 -msse3")
		message (STATUS "  use system ffdecsa sse2 functions")
	elseif (CMAKE_SYSTEM_PROCESSOR MATCHES "(arm)|(ARM)|(aarch64)|(AARCH64)")
		include (CheckIncludeFile)
		check_include_file ("arm_neon.h" HAVE_NEON)
		if (HAVE_NEON)
			if (CMAKE_SYSTEM_PROCESSOR MATCHES "(arm)|(ARM)")
				set(FFDECSA_OPTS "${FFDECSA_OPTS} -mfpu=neon")
			endif (CMAKE_SYSTEM_PROCESSOR MATCHES "(arm)|(ARM)")
			message (STATUS "  use system ffdecsa neon functions")
		endif (HAVE_NEON)
	endif (CMAKE_SYSTEM_PROCESSOR MATCHES "(x86)|(X86)|(amd64)|(AMD64)")
endif (NOT FFDECSA_OPTS)

if (CMAKE_COMPILER_IS_GNUCC)
	set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${FFDECSA_WARN} ${FFDECSA_ERROR} ${FFDECSA_OPTS}")
endif (CMAKE_COMPILER_IS_GNUCC)
#----------------------- FFdecsa files -------------------------------
file (GLOB ffdecsa_srcs "ffdecsa.c")
file (GLOB ffdecsa_hdrs "*.h")
#----------------------- the library ---------------------------------
set (lib_name "ffdecsa")
add_library (${lib_name} STATIC ${ffdecsa_srcs} ${ffdecsa_hdrs})
#----------------------- FFdecsa test file ---------------------------
file (GLOB exe_srcs "ffdecsa_test.c")
#----------------------- the executable ------------------------------
set (exe_name "ffdecsa-test")
add_executable (${exe_name} ${exe_srcs} ${ffdecsa_hdrs})
target_link_libraries (${exe_name} ffdecsa)
#----------------------- printout resume -----------------------------
message (STATUS "")
execute_process(COMMAND ${CMAKE_C_COMPILER} -dumpmachine COMMAND tr -d '\n' OUTPUT_VARIABLE TARGET)
message (STATUS "  ${CMAKE_SYSTEM_NAME}: ${TARGET} (${CMAKE_SYSTEM_PROCESSOR})")
message (STATUS "  FFDECSA_WARN:  ${FFDECSA_WARN}")
message (STATUS "  FFDECSA_ERROR: ${FFDECSA_ERROR}")
message (STATUS "  FFDECSA_OPTS:  ${FFDECSA_OPTS}")
message (STATUS "")
