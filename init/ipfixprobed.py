import yaml
import argparse
import subprocess

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
    return parser.parse_args()

def process_input_plugin(config):
    input_plugin = config.get("input_plugin", {})

    if not isinstance(input_plugin, dict):
        raise ValueError("Invalid input plugin configuration format.")

    if len(input_plugin) != 1:
        raise ValueError("Exactly one input plugin must be specified in the configuration.")

    plugin, settings = next(iter(input_plugin.items()))

    if plugin == "dpdk":
        return process_dpdk_plugin(settings)
    if plugin == "raw":
        return process_raw_plugin(settings)

    params = [f"--{plugin}"]
    for key, value in settings.items():
        if value is not None:
            params.append(f"--{plugin}-{key}={value}")

    return " ".join(params)

def process_dpdk_plugin(settings):
    if "rx_queues" not in settings:
        raise ValueError("Missing required setting: rx_queues")
    rx_queues = settings.get("rx_queues")
    try:
        rx_queues = int(rx_queues)
    except ValueError:
        raise ValueError("rx_queues must be an integer")

    if "allowed_nics" not in settings:
        raise ValueError("Missing required setting: allowed_nics")

    allowed_nics = settings.get("allowed_nics")
    nic_list = allowed_nics.split(",")
    nic_count = len(nic_list)

    params_list = [f"p={','.join(str(i) for i in range(nic_count))}"]

    for key, param_flag in {"burst_size": "b", "mempool_size": "m", "mtu": "mtu"}.items():
        value = settings.get(key)
        if value is not None:
            params_list.append(f"{param_flag}={value}")

    # Generating EAL parameters
    eal_params = [f"-a {nic}" for nic in nic_list]
    eal_opts = settings.get("eal_opts", "")

    eal = " ".join(eal_params)
    if eal_opts:
        eal += f" {eal_opts}"

    # Main parameter for DPDK with $eal_opts
    primary_param = f"-i \"dpdk;p={','.join(str(i) for i in range(nic_count))},"
    primary_param += f"m={settings.get('mempool_size', 8192)},eal={eal}\""

    params = [primary_param] + [f"-i dpdk" for _ in range(rx_queues - 1)]

    return " ".join(params)


def process_raw_plugin(settings):
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
        return process_ipfix_plugin(settings)

    raise ValueError(f"Unsupported output plugin: {plugin}")

def process_ipfix_plugin(settings):
    params = ['-o "ipfix']

    # Main parameters
    host = settings.get("collector", {}).get("host")
    port = settings.get("collector", {}).get("port")
    mtu = settings.get("mtu")
    exporter_id = settings.get("exporter", {}).get("id")
    exporter_dir = settings.get("exporter", {}).get("dir")

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
        template_refresh = protocol["udp"].get("template_refresh")
        if template_refresh is not None:
            params.append(f"template={template_refresh}")
    elif "tcp" in protocol:
        is_tcp = True
        non_blocking = protocol["tcp"].get("non_blocking")
        if non_blocking is not None:
            params.append("non-blocking-tcp")

    # LZ4 compression (only valid with TCP)
    compression = settings.get("compression", {}).get("lz4", {})
    if compression.get("enabled"):
        if not is_tcp:
            raise ValueError("LZ4 compression can only be used with TCP.")
        params.append("lz4-compression")
        buffer_size = compression.get("buffer_size")
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

    # CPU mask
    cpu_mask = general.get("cpu_mask")
    if cpu_mask is not None:
        params.append(f'"--cpus={cpu_mask}"')

    return " ".join(params)


def main():
    try:
        args = parse_args()
        config = load_config(args.config)
        input_params = process_input_plugin(config)
        process_plugin_params = process_process_plugins(config)
        storage_params = process_storage(config)
        output_params = process_output_plugin(config)
        telemetry_params = process_telemetry(config)
        general_params = process_general(config)

        # Output both input plugin and process plugin parameters
        print(input_params)
        print(process_plugin_params)
        print(storage_params)
        print(output_params)
        print(telemetry_params)
        print(general_params)

        command = f"/usr/bin/ipfixprobe {input_params} {process_plugin_params} {storage_params} {output_params} {telemetry_params} {general_params}"
        print(f"Executing: {command}")

        subprocess.run(command, shell=True, check=True)

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        exit(1)

if __name__ == "__main__":
    import sys
    main()
