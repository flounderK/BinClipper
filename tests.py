#!/usr/bin/env python3
import unittest
import binclipper
import binascii
import string
import io
import random
import logging
import sys

log = logging.getLogger("binclippertest")
_handler = logging.StreamHandler()
_handler.setFormatter(logging.Formatter("%(levelname)-7s | %(message)s"))
log.addHandler(_handler)
log.setLevel(logging.DEBUG)


class TestChain(unittest.TestCase):
    def setUp(self):
        self.inp = b'A'*8 + b'B'*4 + b'C'*2 + b'D'*1 + b'E'*16
        self.inpath = io.BytesIO(self.inp)
        self.outpath = io.BytesIO()

    def tearDown(self):
        self.inpath.close()
        self.outpath.close()

    def test_run_chain(self):
        chain_ops = [{"op": "replace",
                      "replace_with_bytes": "cstring:blah",
                      "replace_pattern": "string:AAAAAAAABBBBC",
                      "disable_elastic": True},
                     {"op": "replace",
                      "replace_with_bytes": "hex:5858",
                      "seek": 13}]
        chain = object.__new__(binclipper.Chain)
        chain.chain_description = binclipper.get_chain_args(chain_ops, self.inpath)
        chain.outbuf = chain._get_file_like(chain.chain_description[-1].outpath, "wb")
        chain.seek = 0
        chain.number = -1
        chain.perform_binmod()
        chain.outbuf.seek(0)
        self.assertEqual(chain.outbuf.read(), b'blah\x00CDEEEEEEXXEEEEEEEE')


class TestReplace(unittest.TestCase):
    def setUp(self):
        self.inp = b'A'*8 + b'B'*4 + b'C'*2 + b'D'*1 + b'E'*16
        self.inpath = io.BytesIO(self.inp)
        self.outpath = io.BytesIO()
        log.debug("")
        log.debug("starting test")

    def tearDown(self):
        log.debug("test done")
        log.debug("")
        self.inpath.close()
        self.outpath.close()

    # TODO: add in printing a little bit of debug information if this fails
    def test_replace_bytes(self):
        """Test replacing bytes by seek"""
        log.debug("test_replace_bytes ")
        log.debug("Original input: %s", self.inp)
        byte_input = b'X'*random.randrange(0, 16)
        log.debug("byte_input %s", byte_input)
        seek = random.randrange(0, len(self.inp))
        log.debug("seek %d", seek)
        replacer = binclipper.Replace(self.inpath, self.outpath, byte_input, seek=seek)
        replacer.perform_binmod()
        replacer.outbuf.seek(0)
        byte_output = replacer.outbuf.read()
        log.debug("byte_output %s", byte_output)
        expected_byte_output = self.inp[:seek] + byte_input + self.inp[len(byte_input) + seek:]
        log.debug("expected    %s", expected_byte_output)
        self.assertEqual(byte_output, expected_byte_output)

    def test_replace_bytes_larger_than_input(self):
        """Test replace bytes by seek larger than input"""
        log.debug("test_replace_bytes_larger_than_input")
        log.debug("Original input: %s", self.inp)
        byte_input = b'X'*4
        log.debug("byte_input %s", byte_input)
        seek = 5
        log.debug("seek %s", seek)
        replacer = binclipper.Replace(self.inpath, self.outpath, byte_input, seek=seek, number=len(byte_input) + 3, disable_elastic=True)
        replacer.perform_binmod()
        replacer.outbuf.seek(0)
        byte_output = replacer.outbuf.read()
        log.debug("byte_output %s", byte_output)
        expected_byte_output = self.inp[:seek] + byte_input + self.inp[replacer.number + seek:]
        log.debug("expected    %s", expected_byte_output)
        self.assertEqual(byte_output, expected_byte_output)

    def test_replace_bytes_smaller_than_pattern(self):
        """Test replace bytes with pattern"""
        log.debug("test_replace_bytes_smaller_than_pattern")
        log.debug("Original input: %s", self.inp)
        byte_input = b'cat\x00'
        log.debug("byte_input %s", byte_input)
        replace_pattern = b'AAAAAAB'
        log.debug("replace_pattern %s", replace_pattern)
        replacer = binclipper.Replace(self.inpath, self.outpath, byte_input,
                                      replace_pattern=replace_pattern,
                                      disable_elastic=False)
        replacer.perform_binmod()
        replacer.outbuf.seek(0)
        byte_output = replacer.outbuf.read()
        log.debug("byte_output %s", byte_output)
        expected_byte_output = b'AAcat\x00AABBBB' + b'C'*2 + b'D' + b'E'*16
        log.debug("expected    %s", expected_byte_output)
        self.assertEqual(byte_output, expected_byte_output)


    def test_replace_bytes_equal_size_pattern(self):
        """Test replace bytes with pattern"""
        log.debug("test_replace_bytes_equal_size_pattern")
        log.debug("Original input: %s", self.inp)
        byte_input = b'cat\x00\x00\x00\x00'
        log.debug("byte_input %s", byte_input)
        replace_pattern = b'AAAAAAB'
        log.debug("replace_pattern %s", replace_pattern)
        self.assertEqual(len(byte_input), len(replace_pattern))
        replacer = binclipper.Replace(self.inpath, self.outpath, byte_input,
                                      replace_pattern=replace_pattern,
                                      disable_elastic=False)
        replacer.perform_binmod()
        replacer.outbuf.seek(0)
        byte_output = replacer.outbuf.read()
        log.debug("byte_output %s", byte_output)
        expected_byte_output = b'AAcat\x00\x00\x00\x00BBB' + b'C'*2 + b'D' + b'E'*16
        log.debug("expected    %s", expected_byte_output)
        self.assertEqual(byte_output, expected_byte_output)


class TestSearch(unittest.TestCase):
    def setUp(self):
        self.inp = b'A'*8 + b'B'*4 + b'C'*2 + b'D'*1 + b'E'*16 + b'A'
        self.inpath = io.BytesIO(self.inp)

    def tearDown(self):
        self.inpath.close()

    def test_search(self):
        search_pattern = b'A'
        searcher = binclipper.Search(self.inpath, None, search_pattern)
        searcher.perform_binmod()
        self.assertEqual(searcher.found_offsets, [0, 1, 2, 3, 4, 5, 6, 7, len(self.inp) - 1])


class TestClip(unittest.TestCase):
    def setUp(self):
        self.inp_1 = b'A'*8
        self.inp_2 = b'B'*4
        self.inp_3 = b'C'*2
        self.inp_4 = b'D'*1
        self.inp_5 = b'E'*16
        self.inp = self.inp_1 + self.inp_2 + self.inp_3 + self.inp_4 + self.inp_5
        self.inpath = io.BytesIO(self.inp)
        self.outpath = io.BytesIO()

    def tearDown(self):
        self.inpath.close()

    def test_clip(self):
        seek = random.randrange(0, len(self.inp))
        number = random.randrange(seek, len(self.inp)) - seek
        clipper = binclipper.Clip(self.inpath, self.outpath, seek=seek, number=number)
        clipper.perform_binmod()
        clipper.outbuf.seek(0)
        output = clipper.outbuf.read()
        expected_output = self.inp[seek:seek+number]
        self.assertEqual(expected_output, output)


class TestArgumentParsing(unittest.TestCase):
    def test_replace_args(self):
        in_args = ['-s', '15', 'infile', '--print', 'replace', '64:0x4444444444444444']
        binclipper.parse_args(in_args)

        in_args = ['-s', '15', 'infile', 'outfile', 'replace', '64:0x4444444444444444']
        binclipper.parse_args(in_args)

    def test_search_args(self):
        in_args = ['infile', '--print', 'search', 'hex:6c6c']
        binclipper.parse_args(in_args)

    def test_default_suparser_clip_args(self):
        in_args = ['-s', '15', 'testshellcode', '--print']
        binclipper.parse_args(in_args)


class TestByteInputProcessing(unittest.TestCase):
    def test_int_inputs(self):
        res = binclipper.process_byte_input_and_mode('u8:150')
        self.assertEqual(res, b'\x96')
        res = binclipper.process_byte_input_and_mode('u32:0x11223344')
        self.assertEqual(res, b'D3"\x11')

    def test_int_input_truncation(self):
        """smaller input types should auto truncate input"""
        res = binclipper.process_byte_input_and_mode('u8:0x4444444444444444')
        self.assertEqual(res, b'D')

    def test_hex_inputs(self):
        inp = 'hex:' + binascii.hexlify(string.ascii_letters.encode()).decode()
        res = binclipper.process_byte_input_and_mode(inp).decode()
        self.assertEqual(res, string.ascii_letters)

    def test_string_inputs(self):
        cstr_inp = 'cstring:blah'
        res = binclipper.process_byte_input_and_mode(cstr_inp)
        self.assertEqual(res, b'blah\x00')

        str_inp = 'string:blah'
        res = binclipper.process_byte_input_and_mode(str_inp)
        self.assertEqual(res, b'blah')


if __name__ == "__main__":
    # horrible hack to make the unittest.main output
    # print out after logging is done
    orig_stderr = sys.stderr
    fake_stderr = io.StringIO()
    sys.stderr = fake_stderr

    unittest.main(exit=False)

    # print unittest.main output and reset stderr
    sys.stderr = orig_stderr
    fake_stderr.seek(0)
    orig_stderr.write(fake_stderr.read())

