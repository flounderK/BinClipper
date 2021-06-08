#!/usr/bin/python3
import os
import argparse
import re
import sys
import functools
from abc import ABC, abstractmethod


class BinMod(ABC):
    def __init__(self):
        pass

    @property
    @abstractmethod
    def perform_binmod(self):
        pass


class Clip(BinMod):
    def __init__(self, inpath, outpath, seek=0, number=-1, io_size=0x1000):
        self.inpath = inpath
        self.outpath = outpath
        self.seek = seek
        self.number = number
        self.io_size = io_size

    def perform_binmod(self):
        try:
            read_fd = open(self.inpath, "rb")
            write_fd = open(self.outpath, "wb")
            read_fd.seek(self.seek)
            numread = 0
            readsize = self.io_size if self.number < 0 else self.number
            while read_fd.readable():
                rd = read_fd.read(readsize)
                numread += len(rd)
                write_fd.write(rd)
                if numread >= self.number:
                    break
        finally:
            read_fd.close()
            write_fd.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("inpath", help="Path of file you want to modify")
    parser.add_argument("outpath", help="Path of output")
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
                                           help="Replace bytes at")
    drop_parser = subparsers.add_parser("drop",
                                        help="Ignore \"selected\" bytes, "
                                        "the inverse of the \"clip\" command")
    # set clip as the default behavior
    subparsers.default = "clip"
    # parser.add_argument("-v", "--invert", help="invert")
    args = parser.parse_args()
    print(args)

    # dictionary mapping subparser name to class that will perform behavior
    subparser_handlers = {"clip": Clip,
                          "replace": None,
                          "drop": None}
    # run handler
    handler_class = subparser_handlers.get(args.subparser)
    if handler_class is None:
        raise NotImplementedError()

    # Might be cursed because of undocumented reflection, but comes out clean
    handler_args = handler_class.__init__.__code__.co_varnames
    used_args = {k: v for k, v in args._get_kwargs() if k in handler_args}
    handler = handler_class(**used_args)
    print(handler)
    handler.perform_binmod()


