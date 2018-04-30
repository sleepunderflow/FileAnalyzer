#ifndef ELF_H
#define ELF_H

#include <iostream>
#include <fstream>
#include "elfFlags.h"
using namespace std;

void analyzeElf(char* buffer);
void processHeaders(char* buffers);

int getSize(int type);
unsigned long long getValue(char* buffer, int size);

bool getElfMode(char input);
bool getEncoding(char input);
bool getELFVersion(char input);
bool getOSABI(char input);
bool getObjectFileType(char* buffer);
bool getMachineType(char* buffer);
bool getFileFormatVersion(char* buffer);
bool getEntryPointAddress(char* buffer);
bool getProgramHeaderTableOffset(char* buffer);
bool getSectionHeaderTableOffset(char* buffer);
bool getFlags(char* buffer);
bool getElfHeaderSize(char* buffer);
bool getProgramHeaderEntrySize(char* buffer);
bool getProgramHeaderEntriesNumber(char* buffer);
bool getSectionHeaderEntrySize(char* buffer);
bool getSectionHeaderEntriesNumber(char* buffer);
unsigned long long getSectionHeaderEntryField(unsigned long long sectionID, int fieldID);
int getSectionHeaderFieldSize(int fieldID);
bool getNameStringTableIndex(char* buffer);

#endif
