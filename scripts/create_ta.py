#!/usr/bin/env python3
from argparse import ArgumentParser

import os
import re
import subprocess
import sys
import tempfile
import uuid

verbose = False

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

    parser.add_argument('-v', required=False, action="store_true",
                        default=False,
                        help='Output some verbose debugging info')

    return parser

###############################################################################
# Create TA functions
###############################################################################


def convert_to_header_format(my_uuid):
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
    return "{{ 0x{:08x}, 0x{:04x}, 0x{:04x}," \
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

###############################################################################
# Main function
###############################################################################


def main(argv):
    parser = get_parser()

    args = parser.parse_args()

    if not args.v:
        verbose = True

    if not args.name:
        print("No Trusted Application name provided\n")
        parser.print_help()
        sys.exit(os.EX_USAGE)

    ta_name_upper_case = args.name.upper()
    ta_name_lower_case = args.name.lower()
    print("TA_NAME_UPPER_CASE: {}".format(ta_name_upper_case))
    print("TA_NAME_LOWER_CASE: {}".format(ta_name_lower_case))

    uuid_makefile, uuid_headerfile = create_uuid(args.uuid)
    print("UUID_MAKEFILE: {}".format(uuid_makefile))
    print("UUID_HEADERFILE: {}".format(uuid_headerfile))


if __name__ == "__main__":
    main(sys.argv)
