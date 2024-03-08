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

#include "fuseTelemetry.hpp"

#include <cstring>
#include <iostream>
#include <sstream>
#include <vector>
#include <fuse.h>
#include <errno.h>
#include <memory>
#include <stdexcept>
#include <string>
#include <sys/stat.h>

namespace {

std::vector<std::string> splitPath(const std::string &path, const char delimiter = '/') 
{
    std::vector<std::string> result;
    std::stringstream ss(path);
    std::string item;
    
    while (std::getline(ss, item, delimiter)) {
		if (item.empty()) {
			continue;
		}
        result.push_back(item);
    }
    
    return result;
}

bool isRootPath(const std::string &path) 
{
	return path == "/";
}

std::shared_ptr<ipxp::Telemetry::Node> getLastNode(const std::string &path, std::shared_ptr<ipxp::Telemetry::Directory> rootNode) 
{
	auto paths = splitPath(path);

	std::shared_ptr<ipxp::Telemetry::Directory> dir = rootNode;
	for (size_t idx = 0; idx < paths.size(); idx++) {
		auto node = dir->getEntry(paths[idx]);
		if (!node) {
			return nullptr;
		}
		if (idx == paths.size() - 1) {
			return node;
		}

		dir = std::dynamic_pointer_cast<ipxp::Telemetry::Directory>(node);
		if (!dir) {
			return nullptr;
		}
	}
	return nullptr;
}

} // namespace


namespace ipxp {

std::shared_ptr<Telemetry::Directory> FuseTelemetry::rootNode = nullptr;

static int getattr_callback(const char *path, struct stat *stbuf) 
{
	std::memset(stbuf, 0, sizeof(struct stat));

	if (isRootPath(path)) {
		stbuf->st_mode = S_IFDIR | 0755;
    	stbuf->st_nlink = 2;
    	return 0;
	}

	auto node = getLastNode(path, FuseTelemetry::rootNode);
	if (!node) {
		return -ENOENT;
	}

	auto file = std::dynamic_pointer_cast<Telemetry::File>(node);
	if (file) {
		stbuf->st_mode = S_IFREG | 0777;
		stbuf->st_nlink = 1;
		stbuf->st_size = BUFSIZ;
		return 0;
	}

	auto dir = std::dynamic_pointer_cast<Telemetry::Directory>(node);
	if (dir) {
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
		return 0;
	}

  	return -ENOENT;
}

static int readdir_callback(
	const char *path,
	void *buf,
	fuse_fill_dir_t filler,
    off_t offset,
	struct fuse_file_info *fi) 
{
	(void) offset;
	(void) fi;
	
	filler(buf, ".", NULL, 0);
	filler(buf, "..", NULL, 0);

	if (isRootPath(path)) {
		for (auto entry : FuseTelemetry::rootNode->listEntries()) {
			filler(buf, entry.c_str(), NULL, 0);
		}
		return 0;
	}

	auto node = getLastNode(path, FuseTelemetry::rootNode);
	if (!node) {
		return -ENOENT;
	}

	auto dir = std::dynamic_pointer_cast<Telemetry::Directory>(node);
	if (!dir) {
		return -ENOENT;
	}

	for (auto entry : dir->listEntries()) {
		filler(buf, entry.c_str(), NULL, 0);
	}
	return 0;
}

static int open_callback(const char *path, struct fuse_file_info *fi) 
{
	return 0;
}

static int read_callback(
	const char *path,
	char *buf,
	size_t size,
	off_t offset,
    struct fuse_file_info *fi) 
{
	auto node = getLastNode(path, FuseTelemetry::rootNode);
	if (!node) {
		return -ENOENT;
	}

	auto file = std::dynamic_pointer_cast<Telemetry::File>(node);
	if (!file) {
		return -ENOENT;
	}
	
	std::string contentString = Telemetry::contentToString(file->read());
	contentString += "\n";

	size_t len = contentString.size();
	if ((size_t )offset >= len) {
		return 0;
	}

	if (offset + size > len) {
		std::memcpy(buf, contentString.c_str() + offset, len - offset);
		return len - offset;
	}

	std::memcpy(buf, contentString.c_str() + offset, size);
	return size;
}

static struct fuse_operations fuseOps = {
	.getattr = getattr_callback,
	.open = open_callback,
	.read = read_callback,
	.readdir = readdir_callback,
};

__attribute__((constructor)) static void register_this_plugin()
{
   static PluginRecord rec = PluginRecord("fuse", [](){return new FuseTelemetry();});
   register_plugin(&rec);
}

void FuseTelemetry::init(const char *params)
{
   FuseOptParser parser;
   try {
      parser.parse(params);
   } catch (ParserError &e) {
      throw PluginError(e.what());
   }

   m_mountPoint = parser.mountPoint;

   if (m_mountPoint == "") {
      throw PluginError("Fuse mount point cannot be empty");
   }
}

void FuseTelemetry::start()
{
	if (m_mountPoint.empty()) {
		std::cerr << "Mount point is not set" << std::endl;
		throw PluginError("Mount point is not set");
	}

	std::vector<char*> argv;
	argv.push_back("ipxp-telemetry");
	argv.push_back("-f");
	argv.push_back("-o");
	argv.push_back("auto_unmount");
	argv.push_back(m_mountPoint.data());
	int ret = fuse_main(argv.size(), argv.data(), &fuseOps, NULL);
	if (ret) {
		std::cerr << "Failed to start fuse" << std::endl;
		throw PluginError("Failed to start fuse");
	}
}

} // namespace ipxp
