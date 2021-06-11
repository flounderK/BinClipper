#!/usr/bin/python3
import os
import argparse
import re
import sys
import functools
from abc import ABC, abstractmethod
import binascii
import struct
import ctypes
import io
import logging

log = logging.getLogger("BinClipper")
_handler = logging.StreamHandler()
_handler.setFormatter(logging.Formatter("%(levelname)-7s | %(message)s"))
log.addHandler(_handler)
log.setLevel(logging.WARNING)


# TODO: set outpath(name tbd) as a property
class BinMod(ABC):
    def __init__(self):
        pass

    @property
    @abstractmethod
    def perform_binmod(self):
        pass

    def write_to_stdout(self):
        f = self.outpath
        f.seek(0)
        sys.stdout.buffer.write(f.read())

    def close(self):
        if hasattr(self.outpath, 'closed') and not self.outpath.closed:
            self.outpath.close()
        # if not self.inpath.closed:
        #     self.inpath.close()



class Clip(BinMod):
    def __init__(self, inpath, outpath, seek=0, number=-1, io_size=0x1000):
        self.inpath = inpath
        outbuf = functools.partial(io.FileIO, outpath, "wb") if \
                isinstance(outpath, str) else functools.partial(io.BytesIO)
        self.outpath = outbuf()
        self.seek = seek
        self.number = number
        self.io_size = io_size

    def perform_binmod(self):
        with open(self.inpath, "rb") as read_fd:
            write_fd = self.outpath
            read_fd.seek(self.seek)
            rd = read_fd.read(self.number)
            write_fd.write(rd)
            read_fd.close()


class Replace(BinMod):
    def __init__(self, inpath, outpath, replace_with_bytes, seek=0, number=-1):
        assert isinstance(replace_with_bytes, bytes)
        self.inpath = inpath
        outbuf = functools.partial(io.FileIO, outpath, "wb") if \
                isinstance(outpath, str) else functools.partial(io.BytesIO)
        self.outpath = outbuf()
        self.replace_with_bytes = replace_with_bytes
        self.seek = seek
        self.number = number if number != -1 else len(replace_with_bytes)

    def perform_binmod(self):
        with open(self.inpath, "rb") as read_fd:
            write_fd = self.outpath
            rd = read_fd.read(self.seek)
            write_fd.write(rd)
            write_fd.write(self.replace_with_bytes)
            # current pos + number
            read_fd.seek(self.number, 1)
            write_fd.write(read_fd.read())
            read_fd.close()


def process_byte_input(input_mode, byte_input):
    """Handle the byte input and output bytes"""
    byte_output = None
    ctypes_val = None
    pack = struct.pack
    if input_mode == 'hex':
        return binascii.unhexlify(byte_input)

    byte_input = int(byte_input, 0)
    if input_mode in ['8', 'u8', 's8', 'b', 'B', 'c']:
        ctypes_val = ctypes.c_uint8(byte_input)
    elif input_mode in ['16', 'u16', 's16', 'h', 'H']:
        ctypes_val = ctypes.c_uint16(byte_input)
    elif input_mode in ['32', 'u32', 's32', 'i', 'I']:
        ctypes_val = ctypes.c_uint32(byte_input)
    elif input_mode in ['64', 'u64', 's32', 'q', 'Q']:
        ctypes_val = ctypes.c_uint64(byte_input)
    else:
        raise NotImplementedError("byte input mode not implemented")

    if ctypes_val is not None:
        byte_output = pack(ctypes_val._type_, ctypes_val.value)

    return byte_output


def validate_additional_arg_assertions(args):
    if args.outpath is None and args.print is False:
        raise Exception("Either outpath or print must be provided")
        # raise argparse.ArgumentError("Either outpath or print must be provided")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("inpath", help="Path of file you want to modify")
    parser.add_argument("outpath", help="Path of output", nargs="?")
    parser.add_argument("--print", action="store_true", default=False,
                        help="Print out selected bytes instead of an out file. "
                        "using this option without an outpath will just output "
                        "everything to standard output")
    parser.add_argument("-s", "--seek",
                        help="Seek from the start of the binary to this offset "
                        "before starting your action",
                        type=functools.partial(int, base=0), default=0)
    parser.add_argument("-n", "--number",
                        help="Bytes to include in your action, see individual "
                        "action help messages for details on how this argument "
                        "will effect the output",
                        type=functools.partial(int, base=0), default=-1)
    subparsers = parser.add_subparsers(dest="subparser")
    clip_parser = subparsers.add_parser("clip",
                                        help="Copy \"selected\" bytes to output")
    replace_parser = subparsers.add_parser("replace",
                                           help="Replace NUMBER bytes at the "
                                           "offset of seek. If NUMBER is not provided "
                                           "or is -1, the NUMBER of bytes replaced will "
                                           "be set to the size of the replacing bytes")
    drop_parser = subparsers.add_parser("drop",
                                        help="Ignore \"selected\" bytes, "
                                        "the inverse of the \"clip\" command")
    search_parser = subparsers.add_parser("search",
                                          help="Just search for patterns")
    # TODO: decide on input to support chains

    BYTE_INPUT_MODES = ['hex',
                        '8', 'u8', 's8', 'b', 'B', 'c',
                        '16', 'u16', 's16', 'h', 'H',
                        '32', 'u32', 's32', 'i', 'I',
                        '64', 'u64', 's64', 'q', 'Q']

    BYTE_INPUT_MODES_HELP = "Format of your input. By specifying one of the " \
                            "word options (u64 etc.) the size of your output is set " \
                            "to the size of that word type. All word options are " \
                            "implicitly little endian"

    replace_parser.add_argument("replace_with_mode", choices=BYTE_INPUT_MODES,
                                help=BYTE_INPUT_MODES_HELP)
    replace_parser.add_argument("replace_with_bytes",
                                help="The value that you are replacing the "
                                "selected bytes with")

    parser.add_argument("--debug", action="store_true", default=False)
    # set clip as the default behavior
    subparsers.default = "clip"
    # parser.add_argument("-v", "--invert", help="invert")
    args = parser.parse_args()
    if args.debug is True:
        log.setLevel(logging.DEBUG)
    log.debug(args)
    validate_additional_arg_assertions(args)

    if args.outpath is None:
        args.outpath = io.BytesIO()

    if args.subparser == 'replace':
        # TODO: dirty, fix
        args.replace_with_bytes = process_byte_input(args.replace_with_mode, args.replace_with_bytes)

    # dictionary mapping subparser name to class that will perform behavior
    subparser_handlers = {"clip": Clip,
                          "replace": Replace,
                          "drop": None,
                          "search": None}
    # run handler
    handler_class = subparser_handlers.get(args.subparser)
    if handler_class is None:
        raise NotImplementedError()

    # Might be cursed because of undocumented reflection, but comes out clean
    handler_args = handler_class.__init__.__code__.co_varnames
    used_args = {k: v for k, v in args._get_kwargs() if k in handler_args}
    handler = handler_class(**used_args)
    handler.perform_binmod()
    if args.print is True:
        handler.write_to_stdout()
    handler.close()



