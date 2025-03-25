---
title: OSQUERY
description: List of unirec fields exported together with basic flow fields on interface by OSQUERY plugin.
fields:
  -
    name: "PROGRAM_NAME"
    type: "string"
    ipfix: "8057/852"
    value: " 	The name of the program that handles the connection"
  -
    name: "USERNAME"
    type: "string"
    ipfix: "8057/853"
    value: " 	The name of the user who starts the process"
  -
    name: "OS_NAME"
    type: "string"
    ipfix: "8057/854"
    value: " 	Distribution or product name"
  -
    name: "OS_MAJOR"
    type: "uint16"
    ipfix: "8057/855"
    value: " 	Major release version"
  -
    name: "OS_MINOR"
    type: "uint16"
    ipfix: "8057/856"
    value: " 	Minor release version"
  -
    name: "OS_BUILD"
    type: "string"
    ipfix: "8057/857"
    value: " 	Optional build-specific or variant string"
  -
    name: "OS_PLATFORM"
    type: "string"
    ipfix: "8057/858"
    value: " 	OS Platform or ID"
  -
    name: "OS_PLATFORM_LIKE"
    type: "string"
    ipfix: "8057/859"
    value: " 	Closely related platforms"
  -
    name: "OS_ARCH"
    type: "string"
    ipfix: "8057/860"
    value: " 	OS Architecture"
  -
    name: "KERNEL_VERSION"
    type: "string"
    ipfix: "8057/861"
    value: " 	Kernel version"
  -
    name: "SYSTEM_HOSTNAME"
    type: "string"
    ipfix: "8057/862"
    value: " 	Network hostname including domain"
---
