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
    def test_replace_bytes_samesize(self):
        byte_input = b'X'*random.randrange(0, 16)
        seek = random.randrange(0, len(self.inp))
        replacer = binclipper.Replace(self.inpath, self.outpath, byte_input, seek=seek)
        replacer.perform_binmod()
        replacer.outbuf.seek(0)
        byte_output = replacer.outbuf.read()
        expected_byte_output = self.inp[:seek] + byte_input + self.inp[len(byte_input) + seek:]
        self.assertEqual(byte_output, expected_byte_output)




if __name__ == "__main__":
    unittest.main()
