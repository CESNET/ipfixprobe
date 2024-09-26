FROM rockylinux:9

RUN dnf install -y dnf-plugins-core && \
    dnf copr -y enable @CESNET/NEMEA && \
    dnf install -y epel-release && \
    dnf install -y ipfixprobe nemea && \
    dnf clean all

RUN mkdir -p /output
WORKDIR /output
ENTRYPOINT ["/bin/bash", "-c"]

VOLUME ["/output"]
