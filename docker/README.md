# ipfixprobe Docker wrapper

This repository contains a Docker container that processes network traffic from a pcap file using `ipfixprobe`. It accepts a pcap file and a processing script, runs it inside the container, and outputs the results in CSV format.

## Requirements
 * Docker or Podman
 * bash
 * which, mktemp

## Usage
This container performs the following tasks:
 1. Copies a pcap file and processing script into the container.
 2.	Runs the ipfixprobe tool to export flows.
 3.	Logs the results in CSV format.

### Build

The script builds the image automatically, but be sure that Dockerfile is in the same directory.

To build the manually image, navigate to the directory containing the Dockerfile and run:

```bash
docker build -t docker_ipfixprobe .
```

### Run
To run, use

```bash
bash ./ipfixprobe_wrapper.sh <process_script.sh> <input_file.pcap> <output_file.csv>
```

To process a file `../pcaps/mixed.pcap` using a processing script `process_script.sh` and output the results to `output.csv`, use the following wrapper script:

```bash
bash ./ipfixprobe_wrapper.sh ./process_script.sh ../pcaps/mixed.pcap ./output.csv
```

* `process_script.sh` Script for processing the pcap file inside the container.
* `input_file.pcap` Path to the input pcap file
* `output_file.csv` Path to the output CSV file

### Volumes

The container uses `/output` as a volume to share files between your host system temporary dir (with `mktemp`) and the container.
