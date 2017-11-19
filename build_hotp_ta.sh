#!/bin/bash

CURDIR=`pwd`

# This expects that this is place as a first level folder relative to the other
# OP-TEE folder in a setup using default repo configuration as described by the
# documentation in optee_os (README.md)
ROOT=${PWD}
ROOT=`dirname $ROOT`

# Path to the toolchain
export PATH=${ROOT}/toolchains/aarch32/bin:$PATH

# Path to the TA-DEV-KIT coming from optee_os
export TA_DEV_KIT_DIR=${ROOT}/optee_os/out/arm/export-ta_arm32

# Path to the client library (GP Client API)
export TEEC_EXPORT=${ROOT}/optee_client/out/export

export PLATFORM=vexpress
export PLATFORM_FLAVOR=qemu_virt

# Toolchain prefix for user space code (normal world)
export CROSS_COMPILE=arm-linux-gnueabihf-

# Build the host application
cd $CURDIR/hotp/host
echo $PATH
remake CROSS_COMPILE=${CROSS_COMPILE} $@

# Toolchain prefix for the Trusted Applications
TA_CROSS_COMPILE=arm-linux-gnueabihf-
# Build the Trusted Application
cd $CURDIR/hotp/ta
remake CROSS_COMPILE=${CROSS_COMPILE} $@
