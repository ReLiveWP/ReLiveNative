#
# SignBinary.cmake
# Uses osslsigncode to dual-sign output binaries with SHA1 and SHA256
#

function(sign_target target_name executable_suffix)
    get_target_property(target_path ${target_name} RUNTIME_OUTPUT_NAME)
    if(NOT target_path)
        set(target_path ${target_name})
    endif()

    get_target_property(output_dir ${target_name} RUNTIME_OUTPUT_DIRECTORY)
    if(NOT output_dir)
        set(output_dir ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
    endif()

    set(target_path "${output_dir}/${target_path}")

    set(input_exe "${target_path}${executable_suffix}")
    set(sha1_signed "${target_path}_sha1${executable_suffix}")
    set(final_signed "${target_path}_signed${executable_suffix}")

    set(cert_path "${CMAKE_SOURCE_DIR}/certs/codesign_priv.pfx")
    set(cert_pass "$ENV{CERT_PASSWORD}")
    set(timestamp_url "http://timestamp.digicert.com")

    add_custom_command(
        TARGET ${target_name}
        POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E echo "Dual-signing ${input_exe}"

        COMMAND osslsigncode sign -pkcs12 "${cert_path}" 
            -n "${target_name}"
            -t "${timestamp_url}"
            -in "${input_exe}"
            -out "${sha1_signed}"
            -h sha1
            
        COMMAND osslsigncode sign
            -pkcs12 "${cert_path}"
            -n "${target_name}"
            -ts "${timestamp_url}"
            -in "${sha1_signed}"
            -out "${final_signed}"
            -h sha256
            -nest
            
        COMMAND ${CMAKE_COMMAND} -E copy "${final_signed}" "${input_exe}"
        COMMAND ${CMAKE_COMMAND} -E remove "${sha1_signed}"
        COMMAND ${CMAKE_COMMAND} -E remove "${final_signed}"

        COMMENT "Dual-signed ${target_name} with SHA1 + SHA256"
    )
endfunction()
