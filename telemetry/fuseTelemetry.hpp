/**
 * \file
 * \brief Ipfixprobe telemetry over Fuse 
 * \author Pavel Siska <siska@cesnet.cz>
 * \date 2024
 */
/*
 * Copyright (C) 2024 CESNET
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
 */

#pragma once

#define FUSE_USE_VERSION 30

#include "directory.hpp"

#include <string>
#include <memory>

#include <ipfixprobe/options.hpp>
#include <ipfixprobe/plugin.hpp>

namespace ipxp {

class FuseOptParser : public OptionsParser
{
public:
    std::string mountPoint;

   FuseOptParser() : OptionsParser("fuse", "Fuse telemetry plugin"), mountPoint("")
   {
      register_option("m", "mount-point", "PATH", "Path to mount point",
         [this](const char *arg) { mountPoint = arg; return true; },
         OptionFlags::RequiredArgument);
   }
};

class FuseTelemetry : public Plugin {
public:

	FuseTelemetry() = default;

	void start();

   OptionsParser *get_parser() const override { return new FuseOptParser(); }
   std::string get_name() const override { return "fuse"; }
   void init(const char *params) override;

	static std::shared_ptr<Telemetry::Directory> rootNode;

private:
	std::string m_mountPoint;
};

} // namespace ipxp