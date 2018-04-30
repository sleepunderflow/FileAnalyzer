# FileAnalyzer
Executable files analyzer

## What is this thing?
That application is meant to analyze executable files (currently only supports ELF files) and print as many information about it as possible without decompiling code (so far only analyzes header but the goal is to also add support for sections, program headers etc.)

## Why would I ever need it?
It can be useful for binary exploitation, injecting shellcode when you have a physical access to a binary and probably some more things.

## What's working
- ELF files:
  - Header information (also includes getting *e_shnum* and *e_shstrndx* form 1st section header if applicable)
    - Identifies *e_machine* based on data from [www.sco.com](http://www.sco.com/developers/gabi/latest/ch4.eheader.html) on the 30/04/2018
    - Currently not interpreting *e_flags*
    - When it could be useful gives numbers as both HEX and DEC

## TO-DO
- Interpretation of:
  - Section header's table
  - Program header's table
  - Sections
  - Probably some other stuff
- Modifying some data like names, target machine type, flags
- Semi-automated adding of new sections
- Probably some more stuff as well


## COMPILING
To compile use:
```
make
```

## RUNNING
To run use:
```
./analyzer {filename}
```

### Sample files
There are 3 sample files provided:
```
sampleBinaries/standard
sampleBinaries/largeSectionNumbers
sampleBinaries/bigEndian
```

#### standard
Usage: `./analyzer sampleBinaries/standard`

- Just a standard binary, asks user for input and prints it

#### largeSectionNumbers
Usage: `./analyzer sampleBinaries/largeSectionNumbers`

- standard binary modified to have big big enough *e_shnum* and *e_shstrndx* to use section header at index 0 as source for those values

*Note: only values in few places in a ready binary were modified, no more physical sections were added and section name string index is now wrong, If executed as a file might not work as expected*

#### bigEndian
Usage: `./analyzer sampleBinaries/bigEndian`

- standard binary modified like largeSectionNumbers
- File header modified to use big-endian notation
- Changed some values in a header to get different results

*Note: Values are hard-coded, if executed as a file will not work for sure*

## Sample output (with sampleBinaries/standard as a target file)
```
File Name: sampleBinaries/standard
Size: 8472 bytes
Recognized filetype: ELF

Elf mode: 64-bit
Encoding: little-endian
ELF version: Current version
OS/ABI identifier: No extensions or unspecified
Object file type: Shared object file
Machine type: AMD x86-64 architecture
Object file version: 1
Entry point address: 0x5a0
Program header table's offset: 0x40
Section header table's offset: 0x1998
Processor specific flags: 0x0
ELF header's size: 0x40 (64)
Size of program header table entry: 0x38 (56)
Number of entries in program header table: 0x9 (9)
Program header table's size: 0x1f8 (504)
Size of section header table entry: 0x40 (64)
Number of entries in section header table: 0x1e (30)
Section header table's size: 0x780 (1920)
Section ID of section name string table: 0x1d (29)

```
