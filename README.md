# BinClipper
Modify binary files from the command line:

This script is meant to be a tool to help patch binaries, find patterns in binaries, and in general aid in a lot of the standard things that I do to binaries. More than anything it is meant to streamline the processes of unpacking firmware, reverse engineering, etc. that I could write a whole unique script for (but would prefer not to).



## Help:
```bash
usage: binclipper.py [-h] [-p] [-s SEEK] [-n NUMBER] [--debug]
                     inpath [outpath] {clip,replace,search} ...

positional arguments:
  inpath                Path of file you want to modify
  outpath               Path of output
  {clip,replace,search}
    clip                Copy "selected" bytes to output
    replace             Replace bytes with the ones that you provide. If
                        replace pattern is not provided, replaces NUMBER bytes
                        at the offset of seek. If NUMBER is not provided or is
                        -1, the NUMBER of bytes replaced will be set to the
                        size of the replacing bytes. If replace pattern is
                        provided, replaces the bytes provided with your input
                        bytes NUMBER times, or all instances if NUMBER is left
                        -1
    search              Just search for patterns

optional arguments:
  -h, --help            show this help message and exit
  -p, --print           Print out selected bytes instead of an out file. using
                        this option without an outpath will just output
                        everything to standard output
  -s SEEK, --seek SEEK  Seek from the start of the binary to this offset
                        before starting your action
  -n NUMBER, --number NUMBER
                        Bytes to include in your action, see individual action
                        help messages for details on how this argument will
                        effect the output
  --debug

Examples:
        binclipper.py -s 15 infile.bin outfile.patched.bin replace 64:0x4444444444444444
            ^^^ Replace a qword (8 bytes) 15 bytes into the file with 0x4444444444444444
        binclipper.py infile.bin -p search hex:deadbeef
            ^^^ Search for and print offsets of all instances of \xde\xad\xbe\xef (big endian) in the binary
```


### Planned features for the future
 - specific output mode and additional features for editing values in the procfs file system
 - command chains - pass in a json file with a list of arguments to use for multiple replacements to make a static chain of modifications less tedious to use


