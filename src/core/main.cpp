/**
 * \file
 * \brief Main file of the ipfixprobe exporter
 * \author Jiri Havranek <havranek@cesnet.cz>
 * \date 2025
 * 
 * Copyright (c) 2025 CESNET
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ipfixprobe1.hpp"

#include <ipfixprobe/logger.hpp>

int main(int argc, char *argv[])
{
   ipxp::logger::init();
	auto logger = ipxp::logger::get("main");

   try {
      return ipxp::run(argc, argv);
   } catch (std::runtime_error &ex) {
      logger->error(ex.what());
   }
   return EXIT_FAILURE;
}
