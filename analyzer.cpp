#define FILETYPE_UNKNOWN 0
#define FILETYPE_ELF 1

#include <iostream>
#include <fstream>
#include "elf.h"
using namespace std;

int getFileType(char* buffer);

int main(int argc, char** argv)
{
  if (argc == 1) {
    cout << "You need to provide file name" << endl;
    return 1;
  }

  cout << "File Name: " << argv[1] << endl;
  
  fstream file;
  file.open(argv[1], ios::in | ios::binary);

  // get file length
  file.seekg (0, file.end);
  int length = file.tellg();
  file.seekg (0, file.beg);

  if (length < 4)
    return 1;

  char* buffer = new char[length];
  cout << "Size: " << length << " bytes" << endl;
  file.read(buffer, length);

  bool filetype = getFileType(buffer);

  switch(filetype) {
   case FILETYPE_ELF:
     analyzeElf(buffer);
     break;

   default:
     cout << "Unrecognized file type" << endl;
     return 0;
   }
  
  delete[] buffer;
  
  return 0;
}

int getFileType(char* buffer)
{
  if (buffer[0] == 0x7f && buffer[1] == 0x45 && buffer[2] == 0x4c && buffer[3] == 0x46)
    return FILETYPE_ELF; // elf
  else
    return FILETYPE_UNKNOWN; // not recognized
}
