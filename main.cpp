/**
 * \file main.cpp
 * \brief Main file of the ipfixprobe exporter
 * \author Jiri Havranek <havranek@cesnet.cz>
 * \date 2021
 */
/*
 * Copyright (C) 2021 CESNET
 *
 * LICENSE TERMS
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of the Company nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 *
 *
 */

#include "ipfixprobe.hpp"

int main(int argc, char *argv[])
{
   try {
      return ipxp::run(argc, argv);
   } catch (std::runtime_error &e) {
      std::cerr << "Error: " << e.what() << std::endl;
   }
   return EXIT_FAILURE;
}
