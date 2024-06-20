/**
 * \file cacheoptparser.cpp
 * \brief NHT Flow Cache options parser
 */
/*
 * Copyright (C) 2023 CESNET
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
#include "cacheoptparser.hpp"
#include <cstring>
#include <ipfixprobe/plugin.hpp>
#include <ipfixprobe/utils.hpp>

namespace ipxp {
CacheOptParser::CacheOptParser()
    : OptionsParser("cache", "Storage plugin implemented as a hash table")
    , m_cache_size(1 << DEFAULT_FLOW_CACHE_SIZE)
    , m_line_size(1 << DEFAULT_FLOW_LINE_SIZE)
    , m_active(300)
    , m_inactive(30)
    , m_split_biflow(false)
    , m_periodic_statistics_sleep_time(0)
    , m_enable_fragmentation_cache(true)
    , m_frag_cache_size(10007)
    , // Prime for better distribution in hash table
    m_frag_cache_timeout(3)
{
    register_option(
        "s",
        "size",
        "EXPONENT",
        "Cache size exponent to the power of two",
        [this](const char* arg) {
            try {
                unsigned exp = str2num<decltype(exp)>(arg);
                if (exp < 4 || exp > 30) {
                    throw PluginError("Flow cache size must be between 4 and 30");
                }
                m_cache_size = static_cast<uint32_t>(1) << exp;
            } catch (std::invalid_argument& e) {
                return false;
            }
            return true;
        },
        OptionFlags::RequiredArgument);

    register_option(
        "l",
        "line",
        "EXPONENT",
        "Cache line size exponent to the power of two",
        [this](const char* arg) {
            try {
                m_line_size = static_cast<uint32_t>(1) << str2num<decltype(m_line_size)>(arg);
                if (m_line_size < 1) {
                    throw PluginError("Flow cache line size must be at least 1");
                }
            } catch (std::invalid_argument& e) {
                return false;
            }
            return true;
        },
        OptionFlags::RequiredArgument);

    register_option(
        "a",
        "active",
        "TIME",
        "Active timeout in seconds",
        [this](const char* arg) {
            try {
                m_active = str2num<decltype(m_active)>(arg);
            } catch (std::invalid_argument& e) {
                return false;
            }
            return true;
        },
        OptionFlags::RequiredArgument);

    register_option(
        "i",
        "inactive",
        "TIME",
        "Inactive timeout in seconds",
        [this](const char* arg) {
            try {
                m_inactive = str2num<decltype(m_inactive)>(arg);
            } catch (std::invalid_argument& e) {
                return false;
            }
            return true;
        },
        OptionFlags::RequiredArgument);

    register_option(
        "S",
        "split",
        "",
        "Split biflows into uniflows",
        [this](const char* arg) {
            m_split_biflow = true;
            return true;
        },
        OptionFlags::NoArgument);

    register_option(
        "p",
        "period",
        "TIME",
        "Print cache statistics every period of time.",
        [this](const char* arg) {
            try {
                m_periodic_statistics_sleep_time = str2num<double>(arg);
            } catch (std::invalid_argument& e) {
                return false;
            }
            return true;
        },
        OptionFlags::NoArgument);
    register_option(
        "fe",
        "frag-enable",
        "true|false",
        "Enable/disable fragmentation cache. Enabled (true) by default.",
        [this](const char* arg) {
            if (strcmp(arg, "true") == 0) {
                m_enable_fragmentation_cache = true;
            } else if (strcmp(arg, "false") == 0) {
                m_enable_fragmentation_cache = false;
            } else {
                return false;
            }
            return true;
        },
        OptionFlags::RequiredArgument);

    register_option(
        "fs",
        "frag-size",
        "size",
        "Size of fragmentation cache, must be at least 1. Default value is 10007.",
        [this](const char* arg) {
            try {
                m_frag_cache_size = str2num<decltype(m_frag_cache_size)>(arg);
            } catch (std::invalid_argument& e) {
                return false;
            }
            return m_frag_cache_size > 0;
        });

    register_option(
        "ft",
        "frag-timeout",
        "TIME",
        "Timeout of fragments in fragmentation cache in seconds. Default value is 3.",
        [this](const char* arg) {
            try {
                m_frag_cache_timeout = str2num<decltype(m_frag_cache_timeout)>(arg);
            } catch (std::invalid_argument& e) {
                return false;
            }
            return true;
        });
}
}; // namespace ipxp