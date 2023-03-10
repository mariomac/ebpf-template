#!/usr/bin/env bash

# Version of libbpf to fetch headers from
LIBBPF_VERSION=1.1.0

cd $(dirname "$0")/../bpf/headers

# The headers we want
# Check https://github.com/libbpf/libbpf/tree/master/src for other headers we might want
prefix=libbpf-"$LIBBPF_VERSION"
headers=(
    "$prefix"/LICENSE.BSD-2-Clause
    "$prefix"/src/bpf_endian.h
    "$prefix"/src/bpf_helper_defs.h
    "$prefix"/src/bpf_helpers.h
    "$prefix"/src/bpf_tracing.h
)

# Fetch libbpf release and extract the desired headers
curl -sL "https://github.com/libbpf/libbpf/archive/refs/tags/v${LIBBPF_VERSION}.tar.gz" | \
    tar -xz --xform='s#.*/##' "${headers[@]}"
