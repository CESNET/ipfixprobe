if (!ENABLE_CTT)
    add_subdirectory(cache)
endif()

if (ENABLE_CTT)
    add_subdirectory(cache-ctt)
endif()