#!/bin/bash

# 2018-10-05: Note that due to the recent transition from using cpio directly to
# now use Buildroot instead things have been a bit more complicated building
# using something like this.
# A normal "make" in build.git will put all OP-TEE binaries (except optee_os)
# in: # <root>/out-br/...
#
# A difference now is that the public headers as tee_client_api.h and the
# library libteec.so no longer resides under the same root. Therefore all lines
# having something with $(TEEC_EXPORT)/{include/lib} in all Makefile in this git
# cannot point to the <root>/out-br/ git.
#
# As of now we still support building running:
#   $ make optee-examples-common
# in build.git. Doing so will build and put the h-files needed in the old
# locations. So, to build using this shell script it's not sufficient to just
# run make. One also needs to run the optee-examples-common target. I.e.
#
# 1. In build.git: make
# 2. In build.git: make optee-examples-common
# 3. In optee_examples.git: ./build_hello_world.sh
#
# Note! Don't forget to change paths from <root>/out-br/... to this folder
# instead in case you run GDB or have script doing scp with host + TA's.

clear
echo -e "build.sh\n--------"
echo "args: $@"

CURDIR=`pwd`

# This expects that this is place as a first level folder relative to the other
# OP-TEE folder in a setup using default repo configuration as described by the
# documentation in optee_os (README.md)
ROOT=${PWD}
ROOT=`dirname $ROOT`

TARGET=hello_world
CLEAN=
SYNC=
SHOW_GDB_INFO=true
MOUNT_DIR=

# Can change over time (look for "ELF load address <xyz>" in secure UART)
LOAD_ADDRESS=0x103000

# Path to the toolchain
export PATH=${ROOT}/toolchains/aarch32/bin:${ROOT}/toolchains/aarch64/bin:$PATH

# Path to the TA-DEV-KIT coming from optee_os
export TA_DEV_KIT_DIR=${ROOT}/optee_os/out/arm/export-ta_arm32

# Path to the client library (GP Client API), see main comment above.
export TEEC_EXPORT=${ROOT}/optee_client/out/export

export PLATFORM=vexpress
export PLATFORM_FLAVOR=qemu_virt
export CROSS_COMPILE=arm-linux-gnueabihf-

while getopts a:cd:f:gl:p:ht: option
do
	case "${option}"
		in
		a) echo "Building for AArch${OPTARG}"
		   if [ "${OPTARG}" -eq "64" ] ; then
			export CROSS_COMPILE=aarch64-linux-gnu-
			export TA_DEV_KIT_DIR=${ROOT}/optee_os/out/arm/export-ta_arm64
		   fi;;
		c) CLEAN=clean;;

		d) MOUNT_DIR="NOT_IMPLEMENTED";;

		f) export PLATFORM_FLAVOR=${OPTARG};;

		g) SHOW_GDB_INFO=;;

		l) LOAD_ADDRESS=${OPTARG};;

		p) export PLATFORM=${OPTARG};;

		s) SYNC=true;;

		t) TARGET=${OPTARG};;

		h) echo " -a <32, 64>            default: 32 (architecture)"
		   echo " -c                     clean"
		   echo " -d                     mount point to shared folder with TA's"
		   echo " -f <PLATFORM_FLAVOR>   default: ${PLATFORM_FLAVOR}"
		   echo " -g                     hide GDB string"
		   echo " -l                     Load address of the TA (see secure UART)"
		   echo " -p <PLATFORM>          default: ${PLATFORM}"
		   echo " -s                     run sync"
		   echo " -t <ta-host_to_build>  default: ${TARGET}"
		   exit
		   ;;
	esac
done

# Check that optee_client has been built
if [ ! -d ${TEEC_EXPORT} ]; then
	echo "Error: OP-TEE client hasn't been built"
	echo "  Try: cd ../build && make -j`nproc` optee-client && cd -"
	echo "       then, retry!"
	exit
fi

# Check that optee_os has been built
if [ ! -d ${TA_DEV_KIT_DIR} ]; then
	echo "Error: OP-TEE OS hasn't been built"
	echo "  Try: cd ../build && make -j`nproc` optee-os && cd -"
	echo "       then, retry!"
	exit
fi

echo "Build host and TA for:"
echo "  Target:          ${TARGET}"
echo "  PLATFORM:        ${PLATFORM}"
echo "  PLATFORM_FLAVOR: ${PLATFORM_FLAVOR}"
echo "  CROSS_COMPILE:   ${CROSS_COMPILE}"
echo -e "  LOAD_ADDRESS:    ${LOAD_ADDRESS}\n"

# Build the host application
cd $CURDIR/${TARGET}/host
#export HOST_CROSS_COMPILE=${CROSS_COMPILE}
make CROSS_COMPILE=${CROSS_COMPILE} --no-builtin-variables ${CLEAN}

# Toolchain prefix for the Trusted Applications
#export TA_CROSS_COMPILE=${CROSS_COMPILE}
cd $CURDIR/${TARGET}/ta
make CROSS_COMPILE=${CROSS_COMPILE} ${CLEAN}

# There is no ELF available after running clean, hence exit.
if [ ! -z ${CLEAN} ];then
	exit
fi;

if [ ! -z ${SHOW_GDB_INFO} ]; then
	echo -e "\nGDB target:"
	# Find the TA ELF
	TA_FILE=`ls ${CURDIR}/${TARGET}/ta/*.elf | grep -v stripped`
	# Grab the .text offset
	TA_TEXT_OFFSET=`${CROSS_COMPILE}readelf -S ${TA_FILE} | grep text | head -1 | awk '{print "0x"$5}'`
	# Add it to the load address
	TA_LOAD_ADDRESS=$((${TA_TEXT_OFFSET} + ${LOAD_ADDRESS}))
	echo "   add-symbol-file ${TA_FILE} `printf '0x%08x\n' ${TA_LOAD_ADDRESS}`"
fi;
