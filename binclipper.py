#!/usr/bin/python3
import os
import argparse
import re
import sys
import functools
from abc import ABC, abstractmethod
from collections import namedtuple
import binascii
import struct
import ctypes
import io
import logging
import base64

log = logging.getLogger("BinClipper")
_handler = logging.StreamHandler()
_handler.setFormatter(logging.Formatter("%(levelname)-7s | %(message)s"))
log.addHandler(_handler)
log.setLevel(logging.WARNING)

BYTE_INPUT_SIZE_8 = ['8', 'u8', 's8', 'b', 'B', 'c']
BYTE_INPUT_SIZE_16 = ['16', 'u16', 's16', 'h', 'H']
BYTE_INPUT_SIZE_32 = ['32', 'u32', 's32', 'i', 'I']
BYTE_INPUT_SIZE_64 = ['64', 'u64', 's64', 'q', 'Q']
BYTE_INPUT_BASE64 = ['b64', 'base64']

INPUT_MODE_BYTE_SIZE_LOOKUP = {1: BYTE_INPUT_SIZE_8,
                               2: BYTE_INPUT_SIZE_16,
                               4: BYTE_INPUT_SIZE_32,
                               8: BYTE_INPUT_SIZE_64}

BYTE_INPUT_MODES = ['cstring', 'hex', 'file'] + \
                   BYTE_INPUT_BASE64 + \
                   BYTE_INPUT_SIZE_8 + \
                   BYTE_INPUT_SIZE_16 + \
                   BYTE_INPUT_SIZE_32 + \
                   BYTE_INPUT_SIZE_64

ClipArgs = namedtuple("ClipArgs", ["inpath", "outpath", "seek", "number"])
ClipArgs.__new__.__defaults__ = (-1, 0)

ReplaceArgs = namedtuple("ReplaceArgs", ["inpath", "outpath",
                                         "replace_with_bytes",
                                         "replace_pattern", "seek", "number"])
ReplaceArgs.__new__.__defaults__ = (-1, 0, None)

SearchArgs = namedtuple("SearchArgs", ["inpath", "outpath",
                                       "search_for_bytes", "seek", "number"])
SearchArgs.__new__.__defaults__ = (-1, 0)


class BinMod(ABC):
    def __init__(self):
        pass

    @property
    @abstractmethod
    def perform_binmod(self):
        pass

    @property
    def inbuf(self):
        return self._inbuf

    @inbuf.setter
    def inbuf(self, value):
        self._inbuf = value

    @property
    def outbuf(self):
        return self._outbuf

    @outbuf.setter
    def outbuf(self, value):
        self._outbuf = value

    def write_to_stdout(self):
        f = self.outbuf
        f.seek(0)
        sys.stdout.buffer.write(f.read())

    def _get_file_like(self, inp, open_mode):
        """Depending on the type of input, return something that can be
        treated like a file descriptor (with access mode `open_mode` used
        if relevant)"""
        ret = None
        if isinstance(inp, io.BytesIO) and not inp.closed:
            ret = inp
        elif isinstance(inp, str):
            ret = io.FileIO(inp, open_mode)
        else:
            ret = io.BytesIO()

        return ret

    def _close_if_file(self, iofd):
        if isinstance(iofd, io.FileIO) and iofd.closed is False:
            iofd.close()

    def close_all(self):
        if hasattr(self.inbuf, 'closed') and self.inbuf.closed is False:
            self.inbuf.close()
        if hasattr(self.outbuf, 'closed') and self.outbuf.closed is False:
            self.outbuf.close()

    def close_files(self):
        self._close_if_file(self.outbuf)
        self._close_if_file(self.inbuf)


class Clip(BinMod):
    def __init__(self, inpath, outpath, seek=0, number=-1):
        self.inbuf = self._get_file_like(inpath, "rb")
        self.outbuf = self._get_file_like(outpath, "wb")
        self.seek = seek
        self.number = number

    def perform_binmod(self):
        read_fd = self.inbuf
        write_fd = self.outbuf
        read_fd.seek(self.seek)
        rd = read_fd.read(self.number)
        write_fd.write(rd)


class Replace(BinMod):
    def __init__(self, inpath, outpath, replace_with_bytes, replace_pattern=None, seek=0, number=-1):
        assert isinstance(replace_with_bytes, bytes)
        self.inbuf = self._get_file_like(inpath, "rb")
        self.outbuf = self._get_file_like(outpath, "wb")
        self.replace_with_bytes = replace_with_bytes
        self.replace_pattern = replace_pattern
        self.seek = seek
        # default to the size of replace with bytes so that the size of the end file won't change
        self.number = number if number != -1 else len(replace_with_bytes)

    def perform_binmod(self):
        read_fd = self.inbuf
        write_fd = self.outbuf
        rd = read_fd.read(self.seek)
        write_fd.write(rd)

        if self.replace_pattern is None:
            write_fd.write(self.replace_with_bytes)
            # current pos + number
            read_fd.seek(self.number, 1)
            remainder = read_fd.read()
        else:
            number = 0 if self.number == -1 else self.number
            remainder = read_fd.read()
            log.debug("remainder: %s", remainder)
            escaped_replace_pattern = re.escape(self.replace_pattern)
            log.debug("escaped replace pattern %s"  % repr(escaped_replace_pattern))
            remainder, _ = re.subn(escaped_replace_pattern, self.replace_with_bytes, remainder, number)

        write_fd.write(remainder)


# TODO: this probably shouldn't actually inherit from BinMod, add new class `BinRead`
# TODO: for this and the `Read` class
class Search(BinMod):
    def __init__(self, inpath, outpath, search_for_bytes, seek=0, number=-1):
        assert isinstance(search_for_bytes, bytes)
        self.inbuf = self._get_file_like(inpath, "rb")
        self.outbuf = None
        self.search_for_bytes = search_for_bytes
        self.seek = seek
        self.number = number
        self.found_offsets = []

    def perform_binmod(self):
        read_fd = self.inbuf
        read_fd.seek(self.seek)
        rd = read_fd.read()
        escaped_search_for_bytes = re.escape(self.search_for_bytes)
        for match in re.finditer(escaped_search_for_bytes, rd):
            self.found_offsets.append(match.start())

    def write_to_stdout(self):
        for i in self.found_offsets:
            print("Found at offset %#x" % i)


def get_byte_size_of_input_mode(input_mode):
    for size, modes in INPUT_MODE_BYTE_SIZE_LOOKUP.items():
        if input_mode in modes:
            return size



def process_byte_input_and_mode(byte_input_and_mode):
    """Take in a string containing a combination of a byte input mode and a byte input.
    This takes a form  like 'hex:6c6c' or 'u64:0x4444444'. The byte input mode determines
    what the byte input should be interpreted as"""

    split_byte_input_and_mode = byte_input_and_mode.split(':', 1)
    if len(split_byte_input_and_mode) <= 1:
        raise Exception("Byte input and mode must be in the format '<mode>:<input>'")
    input_mode, byte_input = split_byte_input_and_mode

    if input_mode not in BYTE_INPUT_MODES:
        raise Exception("Byte input mode must be one of the following: %s" % repr(BYTE_INPUT_MODES))

    byte_output = None
    ctypes_val = None
    pack = struct.pack
    if input_mode == 'hex':
        return binascii.unhexlify(byte_input)
    if input_mode == 'file':
        with open(byte_input, "rb") as f:
            content = f.read()
        return content
    if input_mode == 'cstring':
        byte_input = byte_input.encode()
        if not byte_input.endswith(b'\x00'):
            byte_input = byte_input + b'\x00'
            return byte_input
    if input_mode in BYTE_INPUT_BASE64:
        byte_input = base64.b64decode(byte_input)
        return byte_input

    byte_input = int(byte_input, 0)
    if input_mode in BYTE_INPUT_SIZE_8:
        ctypes_val = ctypes.c_uint8(byte_input)
    elif input_mode in BYTE_INPUT_SIZE_16:
        ctypes_val = ctypes.c_uint16(byte_input)
    elif input_mode in BYTE_INPUT_SIZE_32:
        ctypes_val = ctypes.c_uint32(byte_input)
    elif input_mode in BYTE_INPUT_SIZE_64:
        ctypes_val = ctypes.c_uint64(byte_input)
    else:
        raise NotImplementedError("byte input mode not implemented")

    if ctypes_val is not None:
        byte_output = pack(ctypes_val._type_, ctypes_val.value)

    return byte_output


def validate_additional_arg_assertions(args):
    """Things that argparse doesn't support out of the box"""
    # python3.6 argparse prevents getting here, but the intermixed args options
    # will allow for it
    if args.outpath is None:
        args.print = True
    # if args.outpath is None and args.print is False:
    #     raise Exception("Either outpath or print must be provided")
        # raise argparse.ArgumentError("Either outpath or print must be provided")


def parse_args(arguments):
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("inpath", help="Path of file you want to modify")
    parser.add_argument("outpath", help="Path of output", nargs="?")
    # this has to remain to force argparse to move to the next argument after
    # outpath so that outpath can remain an optional positional argument
    parser.add_argument("-p", "--print", action="store_true", default=False,
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
                                           help="Replace bytes with the ones that you provide. "
                                           "If replace pattern is not provided, replaces "
                                           "NUMBER bytes at the "
                                           "offset of seek. If NUMBER is not provided "
                                           "or is -1, the NUMBER of bytes replaced will "
                                           "be set to the size of the replacing bytes. "
                                           "If replace pattern is provided, replaces "
                                           "the bytes provided with your input bytes "
                                           "NUMBER times, or all instances if NUMBER "
                                           "is left -1")
    # waiting on this subparser until the more important features are fleshed out
    # drop_parser = subparsers.add_parser("drop",
    #                                     help="Ignore \"selected\" bytes, "
    #                                     "the inverse of the \"clip\" command")
    search_parser = subparsers.add_parser("search",
                                          help="Just search for patterns")
    # TODO: decide on input to support chains

    EXAMPLE_TEXT = """Examples:
        {0} -s 15 infile.bin outfile.patched.bin replace 64:0x4444444444444444
            ^^^ Replace a qword (8 bytes) 15 bytes into the file with 0x4444444444444444
        {0} infile.bin -p search hex:deadbeef
            ^^^ Search for and print offsets of all instances of \\xde\\xad\\xbe\\xef (big endian) in the binary
    """.format(parser.prog)

    BYTE_INPUT_MODES_HELP = "Format of your input in the form '<mode>:<input>' " \
                            "By specifying one of the " \
                            "word options (u64 etc.) the size of your output is set " \
                            "to the size of that word type. All word options are " \
                            "implicitly little endian. " \
                            "Input modes: %s" % ', '.join([i for i in BYTE_INPUT_MODES])

    replace_parser.add_argument("replace_with_bytes",
                                type=process_byte_input_and_mode, help=BYTE_INPUT_MODES_HELP)

    replace_parser.add_argument("-m", "--replace-pattern", type=process_byte_input_and_mode,
                                help=BYTE_INPUT_MODES_HELP)

    search_parser.add_argument("search_for_bytes",
                               type=process_byte_input_and_mode, help=BYTE_INPUT_MODES_HELP)

    parser.add_argument("--debug", action="store_true", default=False)
    # set clip as the default behavior
    subparsers.default = "clip"
    parser.epilog = EXAMPLE_TEXT
    args = parser.parse_args(arguments)
    if args.debug is True:
        log.setLevel(logging.DEBUG)
    log.debug(args)
    validate_additional_arg_assertions(args)

    return args


if __name__ == "__main__":
    args = parse_args(sys.argv[1:])
    # dictionary mapping subparser name to class that will perform behavior
    subparser_handlers = {"clip": Clip,
                          "replace": Replace,
                          "drop": None,
                          "search": Search,
                          "read": None}
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
    handler.close_all()

