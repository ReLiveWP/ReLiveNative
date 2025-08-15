find_program(OBJCOPY_TOOL ${TOOLCHAIN_PREFIX}-objcopy)
if(NOT OBJCOPY_TOOL)
    message(FATAL_ERROR "objcopy not found")
endif()

function(strip_symbols target)
    add_custom_command(TARGET ${target} POST_BUILD
        COMMAND ${OBJCOPY_TOOL} --only-keep-debug
                 $<TARGET_FILE:${target}>
                 $<TARGET_FILE:${target}>.dbg

        
        # COMMAND cp $<TARGET_FILE:${target}> $<TARGET_FILE:${target}>.dbg

        COMMAND ${OBJCOPY_TOOL} --strip-all
                $<TARGET_FILE:${target}>
        COMMAND ${OBJCOPY_TOOL} --add-gnu-debuglink=$<TARGET_FILE:${target}>.dbg
                $<TARGET_FILE:${target}>
        COMMENT "Splitting debug symbols for ${target}"
    )
endfunction()