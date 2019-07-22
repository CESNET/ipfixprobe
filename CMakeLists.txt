# Author(s): Pavel Benacek <benacek@cesnet.cz>
# Copyright (C) 2018 CESNET
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
# 3. Neither the name of the Company nor the names of its contributors
#    may be used to endorse or promote products derived from this
#    software without specific prior written permission.
#
# This software is provided ``as is'', and any express or implied
# warranties, including, but not limited to, the implied warranties of
# merchantability and fitness for a particular purpose are disclaimed.
# In no event shall the company or contributors be liable for any
# direct, indirect, incidental, special, exemplary, or consequential
# damages (including, but not limited to, procurement of substitute
# goods or services; loss of use, data, or profits; or business
# interruption) however caused and on any theory of liability, whether
# in contract, strict liability, or tort (including negligence or
# otherwise) arising in any way out of the use of this software, even
# if advised of the possibility of such damage.

set (P4E_SOURCES
   p4c-exporter.cpp
   midend.cpp
   utils.cpp
   parser.cpp
   cache.cpp
   exporter.cpp
   plugin.cpp
   types.cpp
)

set (P4E_HEADERS
   options.h
   midend.h
   utils.h
   parser.h
   cache.h
   exporter.h
   plugin.h
   types.h
   unsupported.h
   )

set (P4E_LIBS stdc++fs)
set (IR_DEF_FILES ${IR_DEF_FILES} PARENT_SCOPE)

find_package(nlohmann_json 3.6.1 REQUIRED)
find_package(inja 2.0.0 REQUIRED) # install inja version 2.1.0
find_package(Boost REQUIRED COMPONENTS system filesystem program_options)

add_library(p4e_backend ${P4E_SOURCES})
add_dependencies(p4e_backend genIR frontend)
include_directories(${Boost_INCLUDE_DIRS} ${nlohmann_json_INCLUDE_DIRS} ${inja_INCLUDE_DIRS})
target_link_libraries (p4e_backend ${P4C_LIBRARIES} ${P4C_LIB_DEPS} ${Boost_SYSTEM_LIBRARY} ${Boost_FILESYSTEM_LIBRARY} ${Boost_PROGRAM_OPTIONS_LIBRARY} ${P4E_LIBS} nlohmann_json::nlohmann_json)

add_executable(p4c-p4e p4c-exporter.cpp)
target_link_libraries (p4c-p4e p4e_backend)

install (TARGETS p4c-p4e
  RUNTIME DESTINATION ${P4C_RUNTIME_OUTPUT_DIRECTORY})
