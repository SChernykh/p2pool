if (CMAKE_CXX_COMPILER_ID MATCHES GNU)
	set(GENERAL_FLAGS "-pthread")
	set(WARNING_FLAGS "-Wall -Wextra")

	if (CMAKE_BUILD_TYPE STREQUAL "Debug")
		set(OPTIMIZATION_FLAGS "-O0 -g3")
		if (WITH_COVERAGE)
			set(OPTIMIZATION_FLAGS "${OPTIMIZATION_FLAGS} --coverage")
		endif()
	else()
		set(OPTIMIZATION_FLAGS "-O3 -ffast-math -s")
		if (WITH_LTO)
			set(OPTIMIZATION_FLAGS "${OPTIMIZATION_FLAGS} -flto=auto -fuse-linker-plugin")
		endif()
	endif()

	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${GENERAL_FLAGS} ${WARNING_FLAGS} ${OPTIMIZATION_FLAGS}")
	set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} ${GENERAL_FLAGS} ${WARNING_FLAGS} ${OPTIMIZATION_FLAGS}")

	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${GENERAL_FLAGS} ${WARNING_FLAGS} ${OPTIMIZATION_FLAGS}")
	set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} ${GENERAL_FLAGS} ${WARNING_FLAGS} ${OPTIMIZATION_FLAGS}")

	if (WIN32)
		set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")
	else()
		if (STATIC_BINARY)
			set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")
		else()
			set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libgcc -static-libstdc++")
		endif()
	endif()
elseif (CMAKE_CXX_COMPILER_ID MATCHES MSVC)
	set(GENERAL_FLAGS "")
	set(WARNING_FLAGS "/W4 /sdl")
	set(SECURITY_FLAGS "/GS /guard:cf")
	set(OPTIMIZATION_FLAGS "/O2 /Oi /Ob2 /Ot /DNDEBUG /GL")

	set(CMAKE_C_FLAGS_DEBUG "${GENERAL_FLAGS} ${WARNING_FLAGS} ${SECURITY_FLAGS} /Od /Ob0 /Zi /MTd /fsanitize=address")
	set(CMAKE_CXX_FLAGS_DEBUG "${GENERAL_FLAGS} ${WARNING_FLAGS} ${SECURITY_FLAGS} /Od /Ob0 /Zi /MTd /fsanitize=address")

	set(CMAKE_C_FLAGS_RELEASE "${GENERAL_FLAGS} ${WARNING_FLAGS} ${SECURITY_FLAGS} ${OPTIMIZATION_FLAGS} /MT")
	set(CMAKE_CXX_FLAGS_RELEASE "${GENERAL_FLAGS} ${WARNING_FLAGS} ${SECURITY_FLAGS} ${OPTIMIZATION_FLAGS} /MT")

	set(CMAKE_C_FLAGS_RELWITHDEBINFO "${GENERAL_FLAGS} ${WARNING_FLAGS} ${SECURITY_FLAGS} /Ob1 /Ot /Zi /MT")
	set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "${GENERAL_FLAGS} ${WARNING_FLAGS} ${SECURITY_FLAGS} /Ob1 /Ot /Zi /MT")

elseif (CMAKE_CXX_COMPILER_ID MATCHES Clang)
	if (WIN32)
		set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")
	else()
		set(GENERAL_FLAGS "-pthread")
	endif()

	set(WARNING_FLAGS "-Wall -Wextra -Wno-undefined-internal -Wno-nan-infinity-disabled -Wno-unknown-warning-option")

	if (CMAKE_BUILD_TYPE STREQUAL "Debug")
		set(OPTIMIZATION_FLAGS "-O0 -g3")
	else()
		set(OPTIMIZATION_FLAGS "-O3 -ffast-math -funroll-loops -fmerge-all-constants")

		if (WITH_LTO)
			set(OPTIMIZATION_FLAGS "${OPTIMIZATION_FLAGS} -flto")
		endif()
	endif()

	if (WITH_COVERAGE)
		set(OPTIMIZATION_FLAGS "${OPTIMIZATION_FLAGS} -fprofile-instr-generate -fcoverage-mapping")
	endif()

	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${GENERAL_FLAGS} ${WARNING_FLAGS} ${OPTIMIZATION_FLAGS}")
	set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} ${GENERAL_FLAGS} ${WARNING_FLAGS} ${OPTIMIZATION_FLAGS}")

	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${GENERAL_FLAGS} ${WARNING_FLAGS} ${OPTIMIZATION_FLAGS}")
	set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} ${GENERAL_FLAGS} ${WARNING_FLAGS} ${OPTIMIZATION_FLAGS}")
endif()
