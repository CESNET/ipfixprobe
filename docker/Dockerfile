FROM rockylinux:9

RUN dnf install -y dnf-plugins-core && \
    dnf copr -y enable @CESNET/NEMEA && \
    dnf copr -y enable @CESNET/ipfixprobe && \
    dnf install -y epel-release && \
    dnf install -y ipfixprobe-nemea ipfixprobe-input-pcap ipfixprobe-nemea-process-experimental && \
    dnf install -y ipfixprobe-nemea-output-unirec nemea && \
    dnf clean all

RUN mkdir -p /output
WORKDIR /output
ENTRYPOINT ["/bin/bash", "-c"]

VOLUME ["/output"]
