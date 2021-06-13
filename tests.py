#!/usr/bin/python3
import unittest
import binclipper
import io
import random


class TestReplaceByOffset(unittest.TestCase):
    def setUp(self):
        self.inp = b'A'*8 + b'B'*4 + b'C'*2 + b'D'*1 + b'E'*16
        self.inpath = io.BytesIO(self.inp)
        self.outpath = io.BytesIO()

    def tearDown(self):
        self.inpath.close()
        self.outpath.close()

    # TODO: add in printing a little bit of debug information if this fails
    def test_replace_bytes(self):
        byte_input = b'X'*random.randrange(0, 16)
        seek = random.randrange(0, len(self.inp))
        replacer = binclipper.Replace(self.inpath, self.outpath, byte_input, seek=seek)
        replacer.perform_binmod()
        replacer.outbuf.seek(0)
        byte_output = replacer.outbuf.read()
        expected_byte_output = self.inp[:seek] + byte_input + self.inp[len(byte_input) + seek:]
        self.assertEqual(byte_output, expected_byte_output)

    def test_replace_bytes_larger_than_input(self):
        byte_input = b'X'*4
        seek = 5
        replacer = binclipper.Replace(self.inpath, self.outpath, byte_input, seek=seek, number=len(byte_input) + 3)
        replacer.perform_binmod()
        replacer.outbuf.seek(0)
        byte_output = replacer.outbuf.read()
        expected_byte_output = self.inp[:seek] + byte_input + self.inp[replacer.number + seek:]
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
        in_args = ['-s', '15', 'infile', '--print', 'replace', '64', '0x4444444444444444']
        binclipper.parse_args(in_args)

        in_args = ['-s', '15', 'infile', 'outfile', 'replace', '64', '0x4444444444444444']
        binclipper.parse_args(in_args)

    def test_search_args(self):
        in_args = ['infile', '--print', 'search', 'hex', '6c6c']
        binclipper.parse_args(in_args)

    def test_default_suparser_clip_args(self):
        in_args = ['-s', '15', 'testshellcode', '--print']
        binclipper.parse_args(in_args)



if __name__ == "__main__":
    unittest.main()
