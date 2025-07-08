/**
 * \file ipfixprobe.cpp
 * \brief Main exporter objects source
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

#include "buildConfig.hpp"
#include "stacktrace.hpp"
#include "stats.hpp"

#include <fstream>
#include <future>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <thread>

#include <ipfixprobe/pluginFactory/pluginFactory.hpp>
#include <poll.h>
#include <signal.h>
#include <unistd.h>

namespace ipxp {

volatile sig_atomic_t stop = 0;

volatile sig_atomic_t terminate_export = 0;
volatile sig_atomic_t terminate_input = 0;

const uint32_t DEFAULT_IQUEUE_SIZE = 64;
const uint32_t DEFAULT_OQUEUE_SIZE = 16536;
const uint32_t DEFAULT_FPS = 0; // unlimited

/**
 * \brief Signal handler function.
 * \param [in] sig Signal number.
 */
void signal_handler(int sig)
{
	(void) sig;
	if (sig == SIGSEGV || sig == SIGABRT) {
		st_dump(STDERR_FILENO, sig);
		exit(EXIT_FAILURE);
	}
	stop = 1;
}

void register_handlers()
{
	signal(SIGTERM, signal_handler);
	signal(SIGINT, signal_handler);
	signal(SIGSEGV, signal_handler);
	signal(SIGABRT, signal_handler);
#ifdef WITH_NEMEA
	signal(SIGPIPE, SIG_IGN);
#endif
}

void error(std::string msg)
{
	std::cerr << "Error: " << msg << std::endl;
}

static void printPluginsUsage(const std::vector<PluginManifest>& pluginsManifest)
{
	for (const auto& pluginManifest : pluginsManifest) {
		if (pluginManifest.usage) {
			pluginManifest.usage();
		} else {
			std::cout << pluginManifest.name << std::endl;
		}
		std::cout << std::endl;
	}
}

static bool printPluginUsageByName(
	const std::vector<PluginManifest>& pluginsManifest,
	const std::string& pluginName)
{
	bool found = false;
	for (const auto& pluginManifest : pluginsManifest) {
		if (pluginManifest.name == pluginName) {
			if (pluginManifest.usage) {
				pluginManifest.usage();
			}
			found = true;
		}
	}
	return found;
}

static void printPluginsUsage(const std::string& pluginName)
{
	auto& inputPluginFactory = InputPluginFactory::getInstance();
	auto& storagePluginFactory = StoragePluginFactory::getInstance();
	auto& processPluginFactory = ProcessPluginFactory::getInstance();
	auto& outputPluginFactory = OutputPluginFactory::getInstance();

	bool found = false;

	found |= printPluginUsageByName(inputPluginFactory.getRegisteredPlugins(), pluginName);
	found |= printPluginUsageByName(storagePluginFactory.getRegisteredPlugins(), pluginName);
	found |= printPluginUsageByName(processPluginFactory.getRegisteredPlugins(), pluginName);
	found |= printPluginUsageByName(outputPluginFactory.getRegisteredPlugins(), pluginName);

	if (!found) {
		std::cerr << "No help available for " << pluginName << std::endl;
	}
}

static void printRegisteredPlugins(
	const std::string& pluginType,
	const std::vector<PluginManifest>& pluginsManifest)
{
	std::cout << "Registered " << pluginType << " plugins:" << std::endl;
	for (const auto& pluginManifest : pluginsManifest) {
		std::cout << "  " << pluginManifest.name << std::endl;
	}
	std::cout << "#####################\n";
}

static void printPlugins()
{
	auto& inputPluginFactory = InputPluginFactory::getInstance();
	auto& storagePluginFactory = StoragePluginFactory::getInstance();
	auto& processPluginFactory = ProcessPluginFactory::getInstance();
	auto& outputPluginFactory = OutputPluginFactory::getInstance();

	printRegisteredPlugins("input", inputPluginFactory.getRegisteredPlugins());
	printRegisteredPlugins("storage", storagePluginFactory.getRegisteredPlugins());
	printRegisteredPlugins("process", processPluginFactory.getRegisteredPlugins());
	printRegisteredPlugins("output", outputPluginFactory.getRegisteredPlugins());
}

void print_help(const std::string& arg)
{
	if (arg == "input") {
		auto& inputPluginFactory = InputPluginFactory::getInstance();
		return printPluginsUsage(inputPluginFactory.getRegisteredPlugins());
	}

	if (arg == "storage") {
		auto& storagePluginFactory = StoragePluginFactory::getInstance();
		return printPluginsUsage(storagePluginFactory.getRegisteredPlugins());
	}

	if (arg == "output") {
		auto& outputPluginFactory = OutputPluginFactory::getInstance();
		return printPluginsUsage(outputPluginFactory.getRegisteredPlugins());
	}

	if (arg == "process") {
		auto& processPluginFactory = ProcessPluginFactory::getInstance();
		return printPluginsUsage(processPluginFactory.getRegisteredPlugins());
	}

	return printPluginsUsage(arg);
}

void process_plugin_argline(
	const std::string& args,
	std::string& plugin,
	std::string& params,
	std::vector<int>& affinity)
{
	size_t delim;

	params = args;
	delim = params.find(OptionsParser::DELIM);

	plugin = params.substr(0, delim);
	params.erase(0, delim == std::string::npos ? delim : delim + 1);

	delim = plugin.find('@');
	if (delim != std::string::npos) {
		try {
			affinity.emplace_back(std::stoi(plugin.substr(delim + 1)));
		} catch (const std::invalid_argument& ex) {
			throw IPXPError("CPU affinity must be single number: " + std::string(ex.what()));
		}
	}
	plugin = plugin.substr(0, delim);

	trim_str(plugin);
	trim_str(params);
}

telemetry::Content get_ipx_ring_telemetry(ipx_ring_t* ring)
{
	telemetry::Dict dict;
	uint64_t size = ipx_ring_size(ring);
	uint64_t count = ipx_ring_cnt(ring);
	double usage = 0;
	if (size) {
		usage = (double) count / size * 100;
	}

	dict["size"] = size;
	dict["count"] = count;
	dict["usage"] = telemetry::ScalarWithUnit {usage, "%"};
	return dict;
}

void set_thread_details(pthread_t thread, const std::string& name, const std::vector<int>& affinity)
{
	// Set thread name and affinity
	if (name.length() > 0) {
		pthread_setname_np(thread, name.substr(0, 15).c_str());
	}
	if (affinity.size() > 0) {
		cpu_set_t cpuset;
		CPU_ZERO(&cpuset);
		for (auto cpu : affinity) {
			CPU_SET(cpu, &cpuset);
		}
		int ret = pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset);
		if (ret != 0) {
			throw IPXPError(
				"pthread_setaffinity_np failed, CPU(s) " + vec2str(affinity)
				+ " probably cannot be set");
		}
	}
}

bool process_plugin_args(ipxp_conf_t& conf, IpfixprobeOptParser& parser)
{
	OutputPlugin::ProcessPlugins processPlugins;
	std::string storage_name = "cache";
	std::string storage_params = "";
	std::string output_name = "ipfix";
	std::string output_params = "";

	if (parser.m_storage.size()) {
		std::vector<int> affinity;
		process_plugin_argline(parser.m_storage[0], storage_name, storage_params, affinity);
		if (affinity.size() != 0) {
			throw IPXPError(
				"cannot set CPU affinity for storage plugin (storage plugin is invoked inside "
				"input threads)");
		}
	}
	std::vector<int> output_worker_affinity;
	if (parser.m_output.size()) {
		process_plugin_argline(
			parser.m_output[0],
			output_name,
			output_params,
			output_worker_affinity);
	}

	// Process
	for (auto& it : parser.m_process) {
		std::shared_ptr<ProcessPlugin> processPlugin;
		std::string process_params;
		std::string process_name;
		std::vector<int> affinity;
		process_plugin_argline(it, process_name, process_params, affinity);
		if (affinity.size() != 0) {
			throw IPXPError(
				"cannot set CPU affinity for process plugin (process plugins are invoked "
				"inside "
				"input threads)");
		}
		for (auto& it : processPlugins) {
			std::string plugin_name = it.first;
			if (plugin_name == process_name) {
				throw IPXPError(process_name + " plugin was specified multiple times");
			}
		}
		if (process_name == BASIC_PLUGIN_NAME) {
			continue;
		}

		try {
			auto& processPluginFactory = ProcessPluginFactory::getInstance();
			const int pluginID = ProcessPluginIDGenerator::instance().generatePluginID();
			processPlugin
				= processPluginFactory.createShared(process_name, process_params, pluginID);
			if (processPlugin == nullptr) {
				throw IPXPError("invalid process plugin " + process_name);
			}
			processPlugins.emplace_back(process_name, processPlugin);
		} catch (PluginError& e) {
			throw IPXPError(process_name + std::string(": ") + e.what());
		} catch (PluginExit& e) {
			return true;
		} catch (std::runtime_error& ex) {
			throw IPXPError(process_name + std::string(": ") + ex.what());
		}
	}

	// telemetry
	conf.telemetry_root_node = telemetry::Directory::create();

	// Output
	auto output_dir = conf.telemetry_root_node->addDir("output");
	ipx_ring_t* output_queue = ipx_ring_init(conf.oqueue_size, 1);
	if (output_queue == nullptr) {
		throw IPXPError("unable to initialize ring buffer");
	}

	auto ipxRingTelemetryDir = output_dir->addDir("ipxRing");
	telemetry::FileOps statsOps = {[=]() { return get_ipx_ring_telemetry(output_queue); }, nullptr};
	auto statsFile = ipxRingTelemetryDir->addFile("stats", statsOps);
	conf.holder.add(statsFile);

	std::shared_ptr<OutputPlugin> outputPlugin;

	try {
		auto& outputPluginFactory = OutputPluginFactory::getInstance();
		outputPlugin = outputPluginFactory.createShared(output_name, output_params, processPlugins);
		if (outputPlugin == nullptr) {
			throw IPXPError("invalid output plugin " + output_name);
		}
		conf.outputPlugin = outputPlugin;
	} catch (PluginError& e) {
		throw IPXPError(output_name + std::string(": ") + e.what());
	} catch (PluginExit& e) {
		return true;
	} catch (std::runtime_error& ex) {
		throw IPXPError(output_name + std::string(": ") + ex.what());
	}

	{
		std::promise<WorkerResult>* output_res = new std::promise<WorkerResult>();
		auto output_stats = new std::atomic<OutputStats>();
		conf.output_stats.push_back(output_stats);
		OutputWorker tmp
			= {outputPlugin,
			   new std::thread(
				   output_worker,
				   outputPlugin,
				   output_queue,
				   output_res,
				   output_stats,
				   conf.fps),
			   output_res,
			   output_stats,
			   output_queue};
		set_thread_details(
			tmp.thread->native_handle(),
			"out_" + output_name,
			output_worker_affinity);
		conf.outputs.push_back(tmp);
		conf.output_fut.push_back(output_res->get_future());
	}

	// Input
	auto input_dir = conf.telemetry_root_node->addDir("input");
	auto pipeline_dir = conf.telemetry_root_node->addDir("pipeline");
	auto summary_dir = pipeline_dir->addDir("summary");
	auto flowcache_dir = conf.telemetry_root_node->addDir("flowcache");
	size_t pipeline_idx = 0;
	for (auto& it : parser.m_input) {
		std::shared_ptr<InputPlugin> inputPlugin;
		std::shared_ptr<StoragePlugin> storagePlugin;
		std::string input_params;
		std::string input_name;
		std::vector<int> affinity;
		process_plugin_argline(it, input_name, input_params, affinity);

		auto input_plugin_dir = input_dir->addDir(input_name);
		auto pipeline_queue_dir
			= pipeline_dir->addDir("queues")->addDir(std::to_string(pipeline_idx));

		try {
			auto& inputPluginFactory = InputPluginFactory::getInstance();
			inputPlugin = inputPluginFactory.createShared(input_name, input_params);
			if (inputPlugin == nullptr) {
				throw IPXPError("invalid input plugin " + input_name);
			}
			inputPlugin->set_telemetry_dirs(
				input_plugin_dir,
				pipeline_queue_dir,
				summary_dir,
				pipeline_dir);
			conf.inputPlugins.emplace_back(inputPlugin);
		} catch (PluginError& e) {
			throw IPXPError(input_name + std::string(": ") + e.what());
		} catch (PluginExit& e) {
			return true;
		} catch (std::runtime_error& ex) {
			throw IPXPError(input_name + std::string(": ") + ex.what());
		}

		try {
			auto& storagePluginFactory = StoragePluginFactory::getInstance();
			storagePlugin
				= storagePluginFactory.createShared(storage_name, storage_params, output_queue);
			if (storagePlugin == nullptr) {
				throw IPXPError("invalid storage plugin " + storage_name);
			}
			storagePlugin->set_telemetry_dir(pipeline_queue_dir);
			conf.storagePlugins.emplace_back(storagePlugin);
		} catch (PluginError& e) {
			throw IPXPError(storage_name + std::string(": ") + e.what());
		} catch (PluginExit& e) {
			return true;
		} catch (std::runtime_error& ex) {
			throw IPXPError(storage_name + std::string(": ") + ex.what());
		}

		std::vector<ProcessPlugin*> storage_process_plugins;
		for (auto& it : processPlugins) {
			ProcessPlugin* tmp = it.second->copy();
			storagePlugin->add_plugin(tmp);
			conf.active.process.push_back(tmp);
			conf.active.all.push_back(tmp);
			storage_process_plugins.push_back(tmp);
		}

		std::promise<WorkerResult>* input_res = new std::promise<WorkerResult>();
		conf.input_fut.push_back(input_res->get_future());

		auto input_stats = new std::atomic<InputStats>();
		conf.input_stats.push_back(input_stats);

		WorkPipeline tmp
			= {{inputPlugin,
				new std::thread(
					input_storage_worker,
					inputPlugin,
					storagePlugin,
					conf.iqueue_size,
					conf.max_pkts,
					input_res,
					input_stats),
				input_res,
				input_stats},
			   {storagePlugin, storage_process_plugins}};
		set_thread_details(
			tmp.input.thread->native_handle(),
			"in_" + std::to_string(pipeline_idx) + "_" + input_name,
			affinity);
		conf.pipelines.push_back(tmp);
		pipeline_idx++;
	}

	return false;
}

void finish(ipxp_conf_t& conf)
{
	bool ok = true;

	// Terminate all inputs
	terminate_input = 1;
	for (auto& it : conf.pipelines) {
		it.input.thread->join();
		it.input.inputPlugin->close();
	}

	// Terminate all storages
	for (auto& it : conf.pipelines) {
		for (auto& itp : it.storage.plugins) {
			itp->close();
		}
	}

	// Terminate all outputs
	terminate_export = 1;
	for (auto& it : conf.outputs) {
		it.thread->join();
	}

	for (auto& it : conf.pipelines) {
		it.storage.storagePlugin->close();
	}

	std::cout << "Input stats:" << std::endl
			  << std::setw(3) << "#" << std::setw(13) << "packets" << std::setw(13) << "parsed"
			  << std::setw(20) << "bytes" << std::setw(13) << "dropped" << std::setw(16) << "qtime"
			  << std::setw(7) << "status" << std::endl;

	int idx = 0;
	uint64_t total_packets = 0;
	uint64_t total_parsed = 0;
	uint64_t total_bytes = 0;
	uint64_t total_dropped = 0;
	uint64_t total_qtime = 0;

	for (auto& it : conf.input_fut) {
		WorkerResult res = it.get();
		std::string status = "ok";
		if (res.error) {
			ok = false;
			status = res.msg;
		}
		InputStats stats = conf.input_stats[idx]->load();
		std::cout << std::setw(3) << idx++ << " " << std::setw(12) << stats.packets << " "
				  << std::setw(12) << stats.parsed << " " << std::setw(19) << stats.bytes << " "
				  << std::setw(12) << stats.dropped << " " << std::setw(15) << stats.qtime << " "
				  << std::setw(6) << status << std::endl;
		total_packets += stats.packets;
		total_parsed += stats.parsed;
		total_bytes += stats.bytes;
		total_dropped += stats.dropped;
		total_qtime += stats.qtime;
	}

	std::cout << std::setw(3) << "SUM" << std::setw(13) << total_packets << std::setw(13)
			  << total_parsed << std::setw(20) << total_bytes << std::setw(13) << total_dropped
			  << std::setw(16) << total_qtime << std::endl;

	std::cout << std::endl;

	std::cout << "Output stats:" << std::endl
			  << std::setw(3) << "#" << std::setw(13) << "biflows" << std::setw(13) << "packets"
			  << std::setw(20) << "bytes (L4)" << std::setw(13) << "dropped" << std::setw(7)
			  << "status" << std::endl;

	idx = 0;
	for (auto& it : conf.output_fut) {
		WorkerResult res = it.get();
		std::string status = "ok";
		if (res.error) {
			ok = false;
			status = res.msg;
		}
		OutputStats stats = conf.output_stats[idx]->load();
		std::cout << std::setw(3) << idx++ << " " << std::setw(12) << stats.biflows << " "
				  << std::setw(12) << stats.packets << " " << std::setw(19) << stats.bytes << " "
				  << std::setw(12) << stats.dropped << " " << std::setw(6) << status << std::endl;
	}

	if (!ok) {
		throw IPXPError("one of the plugins exitted unexpectedly");
	}
}

void serve_stat_clients(ipxp_conf_t& conf, struct pollfd pfds[2])
{
	uint8_t buffer[100000];
	size_t written = 0;
	msg_header_t* hdr = (msg_header_t*) buffer;
	int ret = poll(pfds, 2, 0);
	if (ret <= 0) {
		return;
	}
	if (pfds[1].fd > 0 && pfds[1].revents & POLL_IN) {
		ret = recv_data(pfds[1].fd, sizeof(uint32_t), buffer);
		if (ret < 0) {
			// Client disconnected
			close(pfds[1].fd);
			pfds[1].fd = -1;
		} else {
			if (*((uint32_t*) buffer) != MSG_MAGIC) {
				return;
			}
			// Received stats request from client
			written += sizeof(msg_header_t);
			for (auto& it : conf.input_stats) {
				InputStats stats = it->load();
				*(InputStats*) (buffer + written) = stats;
				written += sizeof(InputStats);
			}
			for (auto& it : conf.output_stats) {
				OutputStats stats = it->load();
				*(OutputStats*) (buffer + written) = stats;
				written += sizeof(OutputStats);
			}

			hdr->magic = MSG_MAGIC;
			hdr->size = written - sizeof(msg_header_t);
			hdr->inputs = conf.input_stats.size();
			hdr->outputs = conf.output_stats.size();

			send_data(pfds[1].fd, written, buffer);
		}
	}

	if (pfds[0].revents & POLL_IN) {
		int fd = accept(pfds[0].fd, NULL, NULL);
		if (pfds[1].fd == -1) {
			pfds[1].fd = fd;
		} else if (fd != -1) {
			// Close incoming connection
			close(fd);
		}
	}
}

void main_loop(ipxp_conf_t& conf)
{
	std::vector<std::shared_future<WorkerResult>*> futs;
	for (auto& it : conf.input_fut) {
		futs.push_back(&it);
	}

	struct pollfd pfds[2] = {
		{.fd = -1, .events = POLL_IN, .revents = 0}, // Server
		{.fd = -1, .events = POLL_IN, .revents = 0} // Client
	};

	std::string sock_path = create_sockpath(std::to_string(getpid()).c_str());
	pfds[0].fd = create_stats_sock(sock_path.c_str());
	if (pfds[0].fd < 0) {
		error("Unable to create stats socket " + sock_path);
	}

	while (!stop && futs.size()) {
		serve_stat_clients(conf, pfds);

		for (auto it = futs.begin(); it != futs.end(); it++) {
			std::future_status status = (*it)->wait_for(std::chrono::seconds(0));
			if (status == std::future_status::ready) {
				WorkerResult res = (*it)->get();
				if (!res.error) {
					it = futs.erase(it);
					break;
				}
				stop = 1;
				break;
			}
		}
		for (auto& it : conf.output_fut) {
			std::future_status status = it.wait_for(std::chrono::seconds(0));
			if (status == std::future_status::ready) {
				stop = 1;
				break;
			}
		}

		usleep(1000);
	}

	if (pfds[0].fd != -1) {
		close(pfds[0].fd);
	}
	if (pfds[1].fd != -1) {
		close(pfds[1].fd);
	}
	unlink(sock_path.c_str());
	finish(conf);
}

int run(int argc, char* argv[])
{
	IpfixprobeOptParser parser;
	ipxp_conf_t conf;
	int status = EXIT_SUCCESS;
	const bool loadPluginsRecursive = true;

	register_handlers();

	try {
		parser.parse(argc - 1, const_cast<const char**>(argv) + 1);
	} catch (ParserError& e) {
		error(e.what());
		status = EXIT_FAILURE;
		goto EXIT;
	}

	conf.pluginManager.loadPlugins(parser.m_plugins_path, loadPluginsRecursive);

	// printPlugins();

	if (parser.m_help) {
		if (parser.m_help_str.empty()) {
			parser.usage(std::cout, 0, IPXP_APP_NAME);
		} else {
			print_help(parser.m_help_str);
		}
		goto EXIT;
	}
	if (parser.m_version) {
		std::cout << IPXP_APP_VERSION << std::endl;
		goto EXIT;
	}
	if (parser.m_storage.size() > 1 || parser.m_output.size() > 1) {
		error("only one storage and output plugin can be specified");
		status = EXIT_FAILURE;
		goto EXIT;
	}
	if (parser.m_input.size() == 0) {
		error("specify at least one input plugin");
		status = EXIT_FAILURE;
		goto EXIT;
	}

	if (parser.m_daemon) {
		if (daemon(1, 0) == -1) {
			error("failed to run as a standalone process");
			status = EXIT_FAILURE;
			goto EXIT;
		}
	}
	if (!parser.m_pid.empty()) {
		std::ofstream pid_file(parser.m_pid, std::ofstream::out);
		if (pid_file.fail()) {
			error("failed to write pid file");
			status = EXIT_FAILURE;
			goto EXIT;
		}
		pid_file << getpid();
		pid_file.close();
	}

	if (parser.m_iqueue < 1) {
		error("input queue size must be at least 1 record");
		status = EXIT_FAILURE;
		goto EXIT;
	}
	if (parser.m_oqueue < 1) {
		error("output queue size must be at least 1 record");
		status = EXIT_FAILURE;
		goto EXIT;
	}

	conf.worker_cnt = parser.m_input.size();
	conf.iqueue_size = parser.m_iqueue;
	conf.oqueue_size = parser.m_oqueue;
	conf.fps = parser.m_fps;
	conf.pkt_bufsize = parser.m_pkt_bufsize;
	conf.max_pkts = parser.m_max_pkts;

	set_thread_details(pthread_self(), "", parser.m_cpu_mask);

	try {
		if (process_plugin_args(conf, parser)) {
			goto EXIT;
		}
		if (!parser.m_appfs_mount_point.empty()) {
			bool unmount_on_start = true;
			bool create_directory = true;
			conf.appFs = std::make_unique<telemetry::appFs::AppFsFuse>(
				conf.telemetry_root_node,
				parser.m_appfs_mount_point,
				unmount_on_start,
				create_directory);
			conf.appFs->start();
		}
		main_loop(conf);
		if (!parser.m_appfs_mount_point.empty()) {
			conf.appFs->stop();
		}
	} catch (std::system_error& e) {
		error(e.what());
		status = EXIT_FAILURE;
		goto EXIT;
	} catch (std::bad_alloc& e) {
		error("not enough memory");
		status = EXIT_FAILURE;
		goto EXIT;
	} catch (IPXPError& e) {
		error(e.what());
		status = EXIT_FAILURE;
		goto EXIT;
	}

EXIT:
	if (!parser.m_pid.empty()) {
		unlink(parser.m_pid.c_str());
	}
	return status;
}

} // namespace ipxp
