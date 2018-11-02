#!/usr/bin/env python3
from argparse import ArgumentParser

import datetime
import os
import re
import subprocess
import sys
import uuid

verbose = False
dry_run = False

###############################################################################
# Argument parser
###############################################################################


def get_parser():
    """ Takes care of script argument parsing. """
    parser = ArgumentParser(description='Script used to create Trusted '
                                        'Applications')

    parser.add_argument('-n', '--name', required=False, action="store",
                        default=None,
                        help='The name of the TA to be created')

    parser.add_argument('-u', '--uuid', required=False, action="store",
                        default=None,
                        help='Specific UUID to use')

    parser.add_argument('-d', '--dry-run', required=False, action="store_true",
                        default=False,
                        help='Just output to stdout, do any sed operations')

    parser.add_argument('-v', required=False, action="store_true",
                        default=False,
                        help='Output some verbose debugging info')

    return parser

###############################################################################
# Create TA functions
###############################################################################


def convert_to_header_format(my_uuid):
    global verbose

    if verbose:
        print("time_low: {:08x}".format(my_uuid.time_low))
        print("time_mid: {:04x}".format(my_uuid.time_mid))
        print("time_hi_and_version: {:04x}".format(my_uuid.time_hi_version))
        print("clock_seq_hi_variant: {:02x}".format(
            my_uuid.clock_seq_hi_variant))
        print("clock_seq_low: {:02x}".format(my_uuid.clock_seq_low))
        print("node: {:06x}".format(my_uuid.node))

    node_str = "{:06x}".format(my_uuid.node)
    node_list = [node_str[idx:idx+2]
                 for idx, val in enumerate(node_str) if idx % 2 == 0]
    node_list = ['0x{}'.format(i) for i in node_list]
    node_str = ", ".join(node_list)

    # This is the format that is used in the xyz_ta.h file. Let's construct
    # that.
    # { 0xffffffff, 0xffff, 0xffff,
    #    { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff} }
    return "{{ 0x{:08x}, 0x{:04x}, 0x{:04x}, " \
           "{{ 0x{:02x}, 0x{:02x}, {} }} }}".format(
            my_uuid.time_low,
            my_uuid.time_mid,
            my_uuid.time_hi_version,
            my_uuid.clock_seq_hi_variant,
            my_uuid.clock_seq_low,
            node_str)


def create_uuid(my_uuid):
    new_uuid = uuid.uuid4()

    if my_uuid is not None:
        print("Specific UUID not yet implemented")

    uuid_makefile = str(new_uuid).lower()
    uuid_headerfile = convert_to_header_format(new_uuid)

    return uuid_makefile, uuid_headerfile


def sedify(word_to_replace, ta_name, destination):
    global dry_run
    global verbose

    p1 = subprocess.Popen(["rgrep", "-l", word_to_replace, destination],
                          stdout=subprocess.PIPE)

    output = p1.communicate()[0].decode("utf-8")
    output = output.split("\n")
    # Remove the empty folder
    output.remove('')

    for f in output:
        sed_args = "s/<<<{}>>>/{}/".format(word_to_replace, ta_name)

        if dry_run:
            p2 = subprocess.Popen(["sed", sed_args, f], stdout=subprocess.PIPE)
            if verbose:
                print("\nsed {} {}".format(sed_args, f))
        else:
            p2 = subprocess.Popen(["sed", "-i", sed_args, f],
                                  stdout=subprocess.PIPE)

        output = p2.communicate()[0].decode("utf-8")
        # if verbose:
        #    print(output)


###############################################################################
# Main function
###############################################################################


def main(argv):
    global verbose
    global dry_run

    parser = get_parser()
    args = parser.parse_args()

    if args.v:
        print("Enable verbose")
        verbose = True

    if args.dry_run:
        print("Running dry-run (no sed changes)")
        dry_run = True

    if not args.name:
        print("No Trusted Application name provided\n")
        parser.print_help()
        sys.exit(os.EX_USAGE)

    # Prepare TA name
    ta_name_upper_case = args.name.upper()
    ta_name_lower_case = args.name.lower()
    if verbose:
        print("TA_NAME_UPPER_CASE: {}".format(ta_name_upper_case))
        print("TA_NAME_LOWER_CASE: {}".format(ta_name_lower_case))

    # Prepare UUIDs
    uuid_makefile, uuid_headerfile = create_uuid(args.uuid)
    if verbose:
        print("UUID_MAKEFILE: {}".format(uuid_makefile))
        print("UUID_HEADERFILE: {}".format(uuid_headerfile))

    # Prepare year for copyright
    now = datetime.datetime.now()

    # Calculate source and destination path
    root = os.path.split(os.getcwd())[0]
    dest = "{}/{}".format(root, ta_name_lower_case)
    source = "{}/template".format(os.getcwd())

    if verbose:
        print("src: {}".format(source))
        print("dst: {}".format(dest))

    # Copy the template
    subprocess.call(["cp", "-r", "-f", source, dest])

    conv_array = {
            ("TA_NAME_UPPER_CASE", ta_name_upper_case),
            ("TA_NAME_LOWER_CASE", ta_name_lower_case),
            ("UUID_MAKEFILE", uuid_makefile),
            ("UUID_HEADERFILE", uuid_headerfile),
            ("YEAR", now.year)}

    for i in conv_array:
        sedify(i[0], i[1], dest)

    # Ugly! Fix!
    os.rename(dest + "/ta/include/template_ta.h",
              dest + "/ta/include/" + ta_name_lower_case + "_ta.h")

    os.rename(dest + "/ta/template_ta.c",
              dest + "/ta/" + ta_name_lower_case + "_ta.c")


if __name__ == "__main__":
    main(sys.argv)
