file(GLOB archives "${TEST_DATA_DIR}/*.xz")

foreach(archive ${archives})
	string(REGEX REPLACE "\\.xz$" "" unpacked "${archive}")

	# Already unpacked and up to date
	if(EXISTS "${unpacked}" AND NOT "${archive}" IS_NEWER_THAN "${unpacked}")
		continue()
	endif()

	# -k keeps the archive, so the next build doesn't have to copy it again
	execute_process(
		COMMAND unxz -k -f "${archive}"
		RESULT_VARIABLE result
		OUTPUT_QUIET
		ERROR_QUIET
	)

	if(NOT result EQUAL 0)
		execute_process(
			COMMAND 7z x -y "-o${TEST_DATA_DIR}" "${archive}"
			RESULT_VARIABLE result
			OUTPUT_QUIET
			ERROR_QUIET
		)
	endif()

	if(NOT result EQUAL 0)
		get_filename_component(name "${archive}" NAME)
		message(WARNING "couldn't unpack ${name}: neither unxz nor 7z worked. Unpack it by hand or some tests will fail.")
	endif()
endforeach()
