#!/usr/bin/env python3

import yaml
import argparse
import subprocess
import jsonschema
import json
import re
from pathlib import Path

def load_config(file_path):
    try:
        with open(file_path, 'r') as file:
            return yaml.safe_load(file)
    except FileNotFoundError:
        raise FileNotFoundError(f"Configuration file '{file_path}' not found.")
    except yaml.YAMLError as e:
        raise ValueError(f"Error parsing YAML file: {e}")

def parse_args():
    parser = argparse.ArgumentParser(description="Process input plugin parameters.")
    parser.add_argument("--config", required=True, help="Path to YAML configuration file")
    parser.add_argument("--schema", help="Path to JSON schema file for validation")
    return parser.parse_args()

def process_input_plugin(config):
    input_plugin = config.get("input_plugin", {})

    if not isinstance(input_plugin, dict):
        raise ValueError("Invalid input plugin configuration format.")

    if len(input_plugin) != 1:
        raise ValueError("Exactly one input plugin must be specified in the configuration.")

    plugin, settings = next(iter(input_plugin.items()))

    if plugin == "dpdk":
        return process_input_dpdk_plugin(settings)
    if plugin == "dpdk_ring":
        return process_input_dpdk_ring_plugin(settings)
    if plugin == "raw":
        return process_input_raw_plugin(settings)
    if plugin == "ndp":
        return process_input_ndp_plugin(settings)
    if plugin == "pcap_file":
        return process_input_pcap_file_plugin(settings)
    if plugin == "pcap_live":
        return process_input_pcap_live_plugin(settings)

    params = [f"--{plugin}"]
    for key, value in settings.items():
        if value is not None:
            params.append(f"--{plugin}-{key}={value}")

    return " ".join(params)

def get_cpus_for_pci_device(pci_address: str) -> list[int]:
    """
    Gets the list of CPU IDs associated with the NUMA node corresponding to the given PCI address.

    :param pci_address: PCI address in the format '0000:d8:00.0'
    :return: List of CPU numbers (int) for the corresponding NUMA node
    """
    # Get the NUMA node
    numa_path = Path(f"/sys/bus/pci/devices/{pci_address}/numa_node")
    if not numa_path.exists():
        raise FileNotFoundError(f"NUMA node info for PCI address {pci_address} does not exist.")

    numa_node = numa_path.read_text().strip()
    if numa_node == "-1":
        raise ValueError(f"Device {pci_address} is not assigned to any NUMA node.")

    # Run lscpu to get CPU information
    result = subprocess.run(["lscpu"], capture_output=True, text=True, check=True)
    lines = result.stdout.splitlines()

    # Find the line corresponding to the NUMA node
    pattern = re.compile(rf"NUMA node{numa_node}\s+CPU\(s\):\s+(.*)")
    for line in lines:
        match = pattern.match(line)
        if match:
            cpu_range = match.group(1)
            return parse_cpu_list(cpu_range)

    raise RuntimeError(f"Could not find CPU list for NUMA node {numa_node}.")

def parse_cpu_list(cpu_list_str: str) -> list[int]:
    """
    Converts a CPU range string like "1,3,5-7" to a list of individual CPU numbers [1, 3, 5, 6, 7].

    :param cpu_list_str: The CPU range string
    :return: List of individual CPUs as integers
    """
    cpus = []
    for part in cpu_list_str.split(','):
        if '-' in part:
            start, end = map(int, part.split('-'))
            cpus.extend(range(start, end + 1))
        else:
            cpus.append(int(part))
    return cpus

def process_input_dpdk_plugin(settings):
    rx_queues = settings.get("rx_queues", 1)
    try:
        rx_queues = int(rx_queues)
    except ValueError:
        raise ValueError("rx_queues must be an integer")

    if "allowed_nics" not in settings:
        raise ValueError("Missing required setting: allowed_nics")

    allowed_nics = settings.get("allowed_nics")
    nic_list = allowed_nics.split(",")
    nic_count = len(nic_list)

    # Generating EAL parameters
    eal_params = [f"-a {nic}" for nic in nic_list]
    eal_opts = settings.get("eal_opts", "")

    eal = " ".join(eal_params)
    if eal_opts:
        eal += f" {eal_opts}"

    workers_cpu_list = settings.get("workers_cpu_list")
    if workers_cpu_list:
        if isinstance(workers_cpu_list, str):
            workers_cpu_list = [cpu.strip() for cpu in workers_cpu_list.split(",")]
        elif not isinstance(workers_cpu_list, list):
            raise ValueError("workers_cpu_list must be a list or a comma-separated string")

        if len(workers_cpu_list) != rx_queues:
            raise ValueError("The number of CPUs in workers_cpu_list must match the number of RX queues")
    else:
        cpu_list = get_cpus_for_pci_device(nic_list[0])
        if len(cpu_list) < rx_queues:
            raise ValueError("Not enough CPUs available for the number of RX queues")
        workers_cpu_list = cpu_list[:rx_queues]

    # Main parameter for DPDK with $eal_opts
    primary_param = f"-i \"dpdk;p={','.join(str(i) for i in range(nic_count))};"
    burst_size = settings.get("burst_size", 64)
    if burst_size is not None:
        primary_param += f"b={burst_size};"

    mempool_size = settings.get("mempool_size", 8192)
    if mempool_size is not None:
        primary_param += f"m={mempool_size};"

    mtu = settings.get("mtu", 1518)
    if mtu is not None:
        primary_param += f"mtu={mtu};"
    primary_param += f"eal={eal}\""

    params = []
    first_cpu = workers_cpu_list[0]
    if first_cpu is not None:
        params.append(f"{primary_param}@{first_cpu}")
    else:
        params.append(primary_param)

    for i in range(1, rx_queues):
        cpu = workers_cpu_list[i]
        if cpu is not None:
            params.append(f"-i dpdk@{cpu}")
        else:
            params.append(f"-i dpdk")

    return " ".join(params)

def process_input_dpdk_ring_plugin(settings):
    params = ['-i "dpdk-ring']

    if settings is None:
        raise ValueError("Settings for dpdk_ring plugin cannot be empty.")

    ring_name = settings.get("ring_name")
    if ring_name is None:
        raise ValueError("ring_name must be specified in the dpdk_ring plugin configuration.")

    params.append(f"ring={ring_name}")

    burst_size = settings.get("burst_size", 64)
    if burst_size is not None:
        params.append(f"b={burst_size}")

    eal_opts = settings.get("eal_opts")
    if eal_opts:
        params.append(f"eal={eal_opts}")

    return f'{";".join(params)}"'

def parse_ndp_queues(queues):
    result = []
    for part in queues.split(','):
        part = part.strip()
        if '-' in part:
            start, end = part.split('-')
            result.extend(range(int(start), int(end) + 1))
        elif part:
            result.append(int(part))
    return sorted(result)

def process_input_ndp_plugin(settings):
    params = ['-i "ndp']

    if settings is None:
        raise ValueError("Settings for ndp plugin cannot be empty.")

    device = settings.get("device")
    if device is None:
        raise ValueError("device must be specified in the ndp plugin configuration.")

    queues = settings.get("queues")
    if queues is None:
        raise ValueError("queues must be specified in the ndp plugin configuration.")

    # Parse the queues
    parsed_queues = parse_ndp_queues(queues)

    params = [f'-i "ndp;dev={device}:{queue_id}"' for queue_id in parsed_queues]
    return " ".join(params)

def process_input_pcap_file_plugin(settings):
    params = ['-i "pcap']

    if settings is None:
        raise ValueError("Settings for pcap_file plugin cannot be empty.")

    file = settings.get("file")
    if file is None:
        raise ValueError("file must be specified in the pcap_file plugin configuration.")

    params.append(f"file={file}")

    if "bpf_filter" in settings and settings["bpf_filter"]:
        params.append(f"filter={settings['bpf_filter']}")

    return f'{";".join(params)}"'

def process_input_pcap_live_plugin(settings):
    params = ['-i "pcap']

    if settings is None:
        raise ValueError("Settings for pcap_live plugin cannot be empty.")

    interface = settings.get("interface")
    if interface is None:
        raise ValueError("interface must be specified in the pcap_live plugin configuration.")

    params.append(f"ifc={interface}")

    if "bpf_filter" in settings and settings["bpf_filter"]:
        params.append(f"filter={settings['bpf_filter']}")

    snaplen = settings.get("snap_length", 65535)
    if snaplen is not None:
        params.append(f"snaplen={snaplen}")

    return f'{";".join(params)}"'

def process_input_raw_plugin(settings):
    interfaces = settings.get("interface")
    if not interfaces:
        raise ValueError("At least one interface must be specified in the raw plugin configuration.")

    interfaces_list = interfaces.split(",")

    blocks_count = settings.get("blocks_count")
    packets_in_block = settings.get("packets_in_block")

    params = []
    for interface in interfaces_list:
        param = f"-i \"raw;ifc={interface}\""

        # Add blocks_count and packets_in_block only if they have a value
        if blocks_count:
            param += f";blocks={blocks_count}"
        if packets_in_block:
            param += f";pkts={packets_in_block}"

        params.append(param)

    return " ".join(params)


def process_process_plugins(config):
    process_plugins = config.get("process_plugins", [])

    if not isinstance(process_plugins, list):
        raise ValueError("Invalid process plugins configuration format.")

    params = []
    for plugin_config in process_plugins:
        if isinstance(plugin_config, dict):
            for plugin, settings in plugin_config.items():
                plugin_param_str = f'-p "{plugin}'

                if isinstance(settings, dict):
                    # Add plugin parameters if they exist
                    plugin_params = [f"{key}={value}" for key, value in settings.items() if value is not None]
                    if plugin_params:
                        plugin_param_str += ";" + ";".join(plugin_params)

                params.append(f'{plugin_param_str}"')
        else:
            # If there's no specific plugin parameters, just output the plugin
            params.append(f"-p {plugin_config}")

    return " ".join(params)

def process_storage(config):
    storage = config.get("storage", {})
    if not isinstance(storage, dict):
        raise ValueError("Invalid storage configuration format.")

    params = ['-s "cache']  # Start with "-s cache" for the storage section

    # Cache settings
    cache = storage.get("cache", {})
    if isinstance(cache, dict):
        cache_params = []
        if "size_exponent" in cache:
            cache_params.append(f"s={cache['size_exponent']}")
        if "line_size_exponent" in cache:
            cache_params.append(f"l={cache['line_size_exponent']}")
        if cache_params:
            params.append(f"{';'.join(cache_params)}")

    # Timeouts settings
    timeouts = storage.get("timeouts", {})
    if isinstance(timeouts, dict):
        timeout_params = []
        if "active" in timeouts:
            timeout_params.append(f"a={timeouts['active']}")
        if "inactive" in timeouts:
            timeout_params.append(f"i={timeouts['inactive']}")
        if timeout_params:
            params.append(f"{';'.join(timeout_params)}")

    # Split biflow (flag if true)
    split_biflow = storage.get("split_biflow", None)
    if split_biflow:
        params.append("S")

    # Fragmentation cache settings
    fragmentation_cache = storage.get("fragmentation_cache", {})
    if isinstance(fragmentation_cache, dict):
        if fragmentation_cache.get("enabled"):
            frag_cache_params = []
            if "enabled" in fragmentation_cache:
                frag_cache_params.append(f"fe=true")
            if "size" in fragmentation_cache:
                frag_cache_params.append(f"fs={fragmentation_cache['size']}")
            if "timeout" in fragmentation_cache:
                frag_cache_params.append(f"ft={fragmentation_cache['timeout']}")
            if frag_cache_params:
                params.append(f"{';'.join(frag_cache_params)}")

    # Return the properly joined parameters with semicolons separating all values
    return f'{";".join(params)}"'

def process_output_plugin(config):
    output_plugin = config.get("output_plugin", {})
    if not isinstance(output_plugin, dict):
        raise ValueError("Invalid output plugin configuration format.")

    if len(output_plugin) != 1:
        raise ValueError("Exactly one output plugin must be specified in the configuration.")

    plugin, settings = next(iter(output_plugin.items()))

    if plugin == "ipfix":
        return process_output_ipfix_plugin(settings)

    if plugin == "text":
        return process_output_text_plugin(settings)

    if plugin == "unirec":
        return process_output_unirec_plugin(settings)

    raise ValueError(f"Unsupported output plugin: {plugin}")

def process_output_text_plugin(settings):
    params = ['-o "text']

    if settings is None:
        return f'{";".join(params)}"'

    file = settings.get("file")
    if file is not None:
        params.append(f"file={file}")

    return f'{";".join(params)}"'

def process_output_unirec_plugin(settings):
    raise NotImplementedError("The unirec output plugin configuration is not implemented yet.")

def process_output_ipfix_plugin(settings):
    params = ['-o "ipfix']

    if settings is None:
        return f'{";".join(params)}"'

    # Main parameters
    collector = settings.get("collector")
    if collector is None:
        raise ValueError("collector must be specified in the ipfix plugin configuration.")

    host = collector.get("host")
    if host is None:
        raise ValueError("host must be specified in the ipfix (collector) configuration. ")

    port = collector.get("port")
    if port is None:
        raise ValueError("port must be specified in the ipfix (collector) configuration. ")

    mtu = settings.get("mtu", 1518)
    exporter_id = settings.get("exporter", {}).get("id", 1)
    exporter_dir = settings.get("exporter", {}).get("dir", 0)

    if host is not None:
        params.append(f"host={host}")
    if port is not None:
        params.append(f"port={port}")
    if mtu is not None:
        params.append(f"mtu={mtu}")
    if exporter_id is not None:
        params.append(f"id={exporter_id}")
    if exporter_dir is not None:
        params.append(f"dir={exporter_dir}")

    # Validate that only one protocol is specified
    protocol = settings.get("protocol", {})
    if "udp" in protocol and "tcp" in protocol:
        raise ValueError("Only one protocol (udp or tcp) can be specified, not both.")

    # Process protocol
    is_tcp = False
    if "udp" in protocol:
        params.append("udp")
        udp = protocol.get("udp")
        if udp is not None:
            template_refresh = udp.get("template_refresh", 600)
            if template_refresh is not None:
                params.append(f"template={template_refresh}")
        else:
            template_refresh = 600
            params.append(f"template={template_refresh}")
    elif "tcp" in protocol:
        is_tcp = True
        tcp = protocol.get("tcp")
        if tcp is not None:
            non_blocking = tcp.get("non_blocking", {})
            if non_blocking is not None:
                params.append("non-blocking-tcp")
    else:
        raise ValueError("Invalid options for ipfix protocol. Must be either 'udp' or 'tcp'.")

    # LZ4 compression (only valid with TCP)
    compression = settings.get("compression", {})
    if compression is not None:
        lz4 = compression.get("lz4", {})
        if lz4 is not None:
            if lz4.get("enabled"):
                if not is_tcp:
                    raise ValueError("LZ4 compression can only be used with TCP.")
                params.append("lz4-compression")
                buffer_size = lz4.get("buffer_size")
                if buffer_size is not None:
                    params.append(f"lz4-buffer-size={buffer_size}")

    return f'{";".join(params)}"'

def process_telemetry(config):
    telemetry = config.get("telemetry", {})
    if not isinstance(telemetry, dict):
        raise ValueError("Invalid telemetry configuration format.")

    if "appfs" in telemetry:
        return process_appfs_telemetry(telemetry["appfs"])

    return ""  # No telemetry specified

def process_appfs_telemetry(settings):
    if not isinstance(settings, dict):
        raise ValueError("Invalid appfs telemetry configuration format.")

    enabled = settings.get("enabled", False)
    if not enabled:
        return ""  # Telemetry is disabled, return empty string

    mount_point = settings.get("mount_point")
    if not mount_point:
        raise ValueError("Mount point must be specified when AppFS telemetry is enabled.")

    return f'"--telemetry={mount_point}"'

def process_general(config):
    general = config.get("general", {})
    if not isinstance(general, dict):
        raise ValueError("Invalid general configuration format.")

    params = []

    # Queue sizes
    queues_size = general.get("queues_size", {})
    if isinstance(queues_size, dict):
        if "input" in queues_size:
            params.append(f'"--iqueue={queues_size["input"]}"')
        if "output" in queues_size:
            params.append(f'"--oqueue={queues_size["output"]}"')

    # CPU list
    cpu_list = general.get("cpu_list")
    if cpu_list:
        if isinstance(cpu_list, str):
            cpu_list2 = [cpu.strip() for cpu in cpu_list.split(",")]
            params.append(f'"--cpus={cpu_list}"')
        elif isinstance(cpu_list, list):
            cpu_str = ",".join(str(cpu) for cpu in cpu_list)
            params.append(f'"--cpus={cpu_str}"')
        else:
            raise ValueError("cpu_list must be a list or a comma-separated string")

    return " ".join(params)


def validate_schema(config_file, schema_file):
    try:
        with open(schema_file, 'r') as file:
            schema = json.load(file)
    except FileNotFoundError:
        raise FileNotFoundError(f"Schema file '{schema_file}' not found.")
    except json.JSONDecodeError as e:
        raise ValueError(f"Error parsing JSON schema file: {e}")

    config = load_config(config_file)

    try:
        jsonschema.validate(instance=config, schema=schema)
    except jsonschema.exceptions.ValidationError as e:
        print("Schema validation failed")
        print("Msg:", e.message)
        print("Path:", e.path)
        print("Instance:", e.instance)
        print("Schema:", e.schema)
        exit(1)


def main():
    try:
        args = parse_args()
        if args.schema:
            validate_schema(args.config, args.schema)

        config = load_config(args.config)
        input_params = process_input_plugin(config)
        process_plugin_params = process_process_plugins(config)
        storage_params = process_storage(config)
        output_params = process_output_plugin(config)
        telemetry_params = process_telemetry(config)
        general_params = process_general(config)

        command = f"/usr/bin/ipfixprobe {input_params} {process_plugin_params} {storage_params} {output_params} {telemetry_params} {general_params}"
        print(command)
        return 0

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        exit(1)

if __name__ == "__main__":
    import sys
    main()
