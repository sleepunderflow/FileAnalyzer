#include "elf.h"

char* beginning;
char* sectionHeaderTable;
char* programHeaderTable;

unsigned char EI_CLASS;
unsigned char EI_DATA;
unsigned char EI_VERSION;
unsigned char EI_OSABI;
unsigned long long E_TYPE;
unsigned long long E_MACHINE;
unsigned long long E_VERSION;
unsigned long long E_ENTRY;
unsigned long long E_PHOFF;
unsigned long long E_SHOFF;
unsigned long long E_FLAGS;
unsigned long long E_EHSIZE;
unsigned long long E_PHENTSIZE;
unsigned long long E_PHNUM;
unsigned long long E_SHENTSIZE;
unsigned long long E_SHNUM;
unsigned long long E_SHSTRNDX;

void analyzeElf(char* buffer)
{
  cout << "Recognized filetype: ELF" << endl << endl;
  
  processHeaders(buffer);

  
}

void processHeaders(char* buffer)
{
  beginning = buffer;
  buffer += 0x04; // get past header
  //0x04
  if (!getElfMode(*buffer))
    return;
  buffer++;

  // 0x05
  if (!getEncoding(*buffer))
    return;
  buffer++;

  // 0x06
  if (!getELFVersion(*buffer))
    return;
  buffer++;

  // 0x07
  if (!getOSABI(*buffer))
    return;
  buffer++;

  // skip padding bytes
  buffer += 0x08;

  // 0x010 - 0x011
  if (!getObjectFileType(buffer))
    return;
  buffer += getSize(ELF_HALF);

  // 0x012 - 0x013
  if (!getMachineType(buffer))
    return;
  buffer += getSize(ELF_HALF);

  // 0x014 - 0x017
  if (!getFileFormatVersion(buffer))
    return;
  buffer += getSize(ELF_WORD);

  // 0x018 - 0x01F
  if (!getEntryPointAddress(buffer))
    return;
  buffer += getSize(ELF_ADDR);

  //From this point offsets depend on whether it's 32 or 64-bit
  if (!getProgramHeaderTableOffset(buffer))
    return;
  buffer += getSize(ELF_OFF);

  if (!getSectionHeaderTableOffset(buffer))
    return;
  buffer += getSize(ELF_OFF);

  if (!getFlags(buffer))
    return;
  buffer += getSize(ELF_WORD);

  if (!getElfHeaderSize(buffer))
    return;
  buffer += getSize(ELF_HALF);

  if (!getProgramHeaderEntrySize(buffer))
    return;
  buffer += getSize(ELF_HALF);

  if (!getProgramHeaderEntriesNumber(buffer))
    return;
  buffer += getSize(ELF_HALF);

  unsigned long long phsize = E_PHENTSIZE * E_PHNUM;
  cout << "Program header table's size: 0x" << hex << phsize << " (" << dec << phsize << ")" << endl;

  if (!getSectionHeaderEntrySize(buffer))
    return;
  buffer += getSize(ELF_HALF);

  if (!getSectionHeaderEntriesNumber(buffer))
    return;
  buffer += getSize(ELF_HALF);

  unsigned long long shsize = E_SHENTSIZE * E_SHNUM;
  cout << "Section header table's size: 0x" << hex << shsize << " (" << dec << shsize << ")" << endl;

  if (!getNameStringTableIndex(buffer))
    return;
  buffer += getSize(ELF_HALF);
}

bool getElfMode(char input)
{
  cout << "Elf mode: ";
  EI_CLASS = input;
  switch (EI_CLASS) {
    case ELFCLASSNONE:
      cout << "Invalid class" << endl;
      return false;
    case ELFCLASS32:
      cout << "32-bit" << endl;
      break;
    case ELFCLASS64:
      cout << "64-bit" << endl;
      break;
    default:
      cout << "Unrecognized" << endl;
      return false;
    }
  return true;
}

bool getEncoding(char input)
{
  cout << "Encoding: ";
  EI_DATA = input;
  switch (EI_DATA) {
    case ELFDATANONE:
      cout << "Invalid data encoding" << endl;
      return false;
    case ELFDATA2LSB:
      cout << "little-endian" << endl;
      break;
    case ELFDATA2MSB:
      cout << "big-endian" << endl;
      break;
    default:
      cout << "Unrecognized" << endl;
      return false;
    }
  return true;
}

bool getELFVersion(char input)
{
  cout << "ELF version: ";
  EI_VERSION = input;
  switch (EI_VERSION) {
    case EV_NONE:
      cout << "Invalid version" << endl;
      return false;
    case EV_CURRENT:
      cout << "Current version" << endl;
      break;
    default:
      cout << "Unrecognized" << endl;
      return false;
    }
  return true;
}

bool getOSABI(char input)
{
  cout << "OS/ABI identifier: ";
  EI_OSABI = input;
  switch (EI_OSABI) {
    case ELFOSABI_NONE:
      cout << "No extensions or unspecified" << endl;
      break;
    case ELFOSABI_HPUX:
      cout << "Hewlett-Packard HP_UX" << endl;
      break;
    case ELFOSABI_NETBSD:
      cout << "NetBSD" << endl;
      break;
    case ELFOSABI_GNU:
      cout << "GNU" << endl;
      break;
    case ELFOSABI_SOLARIS:
      cout << "Sun Solaris" << endl;
      break;
    case ELFOSABI_AIX:
      cout << "AIX" << endl;
      break;
    case ELFOSABI_IRIX:
      cout << "IRIX" << endl;
      break;
    case ELFOSABI_FREEBSD:
      cout << "FreeBSD" << endl;
      break;
    case ELFOSABI_TRU64:
      cout << "Compaq TRU64 UNIX" << endl;
      break;
    case ELFOSABI_MODESTO:
      cout << "Novell Modesto" << endl;
      break;
    case ELFOSABI_OPENBSD:
      cout << "Open BSD" << endl;
      break;
    case ELFOSABI_OPENVMS:
      cout << "Open VMS" << endl;
      break;
    case ELFOSABI_NSK:
      cout << "Hewlett-Packard Non-Stop Kernel" << endl;
      break;
    case ELFOSABI_AROS:
      cout << "Amiga Research OS" << endl;
      break;
    case ELFOSABI_FENIXOS:
      cout << "The FenixOS highly scalable multi-core OS" << endl;
      break;
    case ELFOSABI_CLOUDABI:
      cout << "Nuxi CloudABI" << endl;
      break;
    case ELFOSABI_OPENVOS:
      cout << "Stratus Technologies OpenVOS" << endl;
      break;
    default:
      if (EI_OSABI > 64 && EI_OSABI <= 255)
	cout << "Architecture-specific value" << endl;
      else {
	cout << "Unrecognized value" << endl;
	return false;
      }
    }
  return true;
}

int getSize(int type)
{
  if (EI_CLASS == ELFCLASS32) {
    switch (type) {
    case ELF_ADDR:
      return ELF32_ADDR;
    case ELF_OFF:
      return ELF32_OFF;
    case ELF_HALF:
      return ELF32_HALF;
    case ELF_WORD:
      return ELF32_WORD;
    case ELF_SWORD:
      return ELF32_SWORD;
    case ELF_XWORD:
      return ELF32_WORD; // As there's no xword in 32-bit, word is used instead
    case ELF_SXWORD:
      return ELF32_SWORD; // As there's no sxword in 32-bit, sword is used instead
    }
  }
  if (EI_CLASS == ELFCLASS64) {
    switch (type) {
    case ELF_ADDR:
      return ELF64_ADDR;
    case ELF_OFF:
      return ELF64_OFF;
    case ELF_HALF:
      return ELF64_HALF;
    case ELF_WORD:
      return ELF64_WORD;
    case ELF_SWORD:
      return ELF64_SWORD;
    case ELF_XWORD:
      return ELF64_XWORD;
    case ELF_SXWORD:
      return ELF64_SXWORD;
    }
  }

  return 0;
}

unsigned long long getValue(char* buffer, int size)
{
  unsigned long long value;
  value = 0;
  if (EI_DATA == ELFDATA2LSB) {
    //buffer += (size-1);
    for (int i = size-1; i >= 0; i--) {
      value <<= 8;
      unsigned char next = buffer[i];
      value += next;
    }
    return value;
  }
  if (EI_DATA == ELFDATA2MSB) {
    for (int i = 0; i < size; i++) {
      value <<= 8;
      unsigned char next = buffer[i];
      value += next;
    }
    return value;
  }
  return 0;
}

bool getObjectFileType(char* buffer)
{
  cout << "Object file type: ";
  unsigned long long value;
  value = getValue(buffer, getSize(ELF_HALF));
  E_TYPE = value;
  switch (E_TYPE) {
  case ET_NONE:
    cout << "No file type" << endl;
    break;
  case ET_REL:
    cout << "Relocatable file" << endl;
    break;
  case ET_EXEC:
    cout << "Executable file" << endl;
    break;
  case ET_DYN:
    cout << "Shared object file" << endl;
    break;
  case ET_CORE:
    cout << "Core file" << endl;
    break;
  default:
    if (E_TYPE >= ET_LOPROC && E_TYPE <= ET_HIPROC) {
      cout << "Processor specific" << endl;
      return true;
    }
    if (E_TYPE >= ET_LOOS && E_TYPE <= ET_HIOS) {
      cout << "Operating system specific" << endl;
      return true;
    }
    cout << "Unrecognized" << endl;
    return false;
  }
  return true;
}


bool getMachineType(char* buffer)
{
  cout << "Machine type: ";
  unsigned long long value;
  value = getValue(buffer, getSize(ELF_HALF));
  E_MACHINE = value;
  switch (E_MACHINE) {
  case EM_NONE:          cout << "No machine" << endl; break;
  case EM_M32:	         cout << "AT&T WE 32100" << endl; break;
  case EM_SPARC:	 cout << "SPARC" << endl; break;
  case EM_386:  	 cout << "Intel 80386" << endl; break;
  case EM_68K:       	 cout << "Motorola 68000" << endl; break;
  case EM_88K:       	 cout << "Motorola 88000" << endl; break;
  case EM_IAMCU: 	 cout << "Intel MCU" << endl; break;
  case EM_860: 	         cout << "Intel 80860" << endl; break;
  case EM_MIPS: 	 cout << "MIPS I Architecture" << endl; break;
  case EM_S370: 	 cout << "IBM System/370 Processor" << endl; break;
  case EM_MIPS_RS3_LE: 	 cout << "MIPS RS3000 Little-endian" << endl; break;
  case EM_PARISC: 	 cout << "Hewlett-Packard PA-RISC" << endl; break;
  case EM_VPP500: 	 cout << "Fujitsu VPP500" << endl; break;
  case EM_SPARC32PLUS: 	 cout << "Enhanced instruction set SPARC" << endl; break;
  case EM_960:       	 cout << "Intel 80960" << endl; break;
  case EM_PPC:       	 cout << "PowerPC" << endl; break;
  case EM_PPC64: 	 cout << "64-bit PowerPC" << endl; break;
  case EM_S390: 	 cout << "IBM System/390 Processor" << endl; break;
  case EM_SPU:       	 cout << "IBM SPU/SPC" << endl; break;
  case EM_V800: 	 cout << "NEC V800" << endl; break;
  case EM_FR20: 	 cout << "Fujitsu FR20" << endl; break;
  case EM_RH32: 	 cout << "TRW RH-32" << endl; break;
  case EM_RCE:       	 cout << "Motorola RCE" << endl; break;
  case EM_ARM:       	 cout << "ARM 32-bit architecture (AARCH32)" << endl; break;
  case EM_ALPHA: 	 cout << "Digital Alpha" << endl; break;
  case EM_SH:       	 cout << "Hitachi SH" << endl; break;
  case EM_SPARCV9: 	 cout << "SPARC Version 9" << endl; break;
  case EM_TRICORE: 	 cout << "Siemens TriCore embedded processor" << endl; break;
  case EM_ARC:       	 cout << "Argonaut RISC Core, Argonaut Technologies Inc." << endl; break;
  case EM_H8_300: 	 cout << "Hitachi H8/300" << endl; break;
  case EM_H8_300H: 	 cout << "Hitachi H8/300H" << endl; break;
  case EM_H8S:       	 cout << "Hitachi H8S" << endl; break;
  case EM_H8_500: 	 cout << "Hitachi H8/500" << endl; break;
  case EM_IA_64: 	 cout << "Intel IA-64 processor architecture" << endl; break;
  case EM_MIPS_X: 	 cout << "Stanford MIPS-X" << endl; break;
  case EM_COLDFIRE: 	 cout << "Motorola ColdFire" << endl; break;
  case EM_68HC12: 	 cout << "Motorola M68HC12" << endl; break;
  case EM_MMA:       	 cout << "Fujitsu MMA Multimedia Accelerator" << endl; break;
  case EM_PCP:       	 cout << "Siemens PCP" << endl; break;
  case EM_NCPU: 	 cout << "Sony nCPU embedded RISC processor" << endl; break;
  case EM_NDR1: 	 cout << "Denso NDR1 microprocessor" << endl; break;
  case EM_STARCORE: 	 cout << "Motorola Star*Core processor" << endl; break;
  case EM_ME16: 	 cout << "Toyota ME16 processor" << endl; break;
  case EM_ST100: 	 cout << "STMicroelectronics ST100 processor" << endl; break;
  case EM_TINYJ: 	 cout << "Advanced Logic Corp. TinyJ embedded processor family" << endl; break;
  case EM_X86_64: 	 cout << "AMD x86-64 architecture" << endl; break;
  case EM_PDSP: 	 cout << "Sony DSP Processor" << endl; break;
  case EM_PDP10: 	 cout << "Digital Equipment Corp. PDP-10" << endl; break;
  case EM_PDP11: 	 cout << "Digital Equipment Corp. PDP-11" << endl; break;
  case EM_FX66: 	 cout << "Siemens FX66 microcontroller" << endl; break;
  case EM_ST9PLUS: 	 cout << "STMicroelectronics ST9+ 8/16 bit microcontroller" << endl; break;
  case EM_ST7:       	 cout << "STMicroelectronics ST7 8-bit microcontroller" << endl; break;
  case EM_68HC16: 	 cout << "Motorola MC68HC16 Microcontroller" << endl; break;
  case EM_68HC11: 	 cout << "Motorola MC68HC11 Microcontroller" << endl; break;
  case EM_68HC08: 	 cout << "Motorola MC68HC08 Microcontroller" << endl; break;
  case EM_68HC05: 	 cout << "Motorola MC68HC05 Microcontroller" << endl; break;
  case EM_SVX:       	 cout << "Silicon Graphics SVx" << endl; break;
  case EM_ST19: 	 cout << "STMicroelectronics ST19 8-bit microcontroller" << endl; break;
  case EM_VAX:       	 cout << "Digital VAX" << endl; break;
  case EM_CRIS: 	 cout << "Axis Communications 32-bit embedded processor" << endl; break;
  case EM_JAVELIN: 	 cout << "Infineon Technologies 32-bit embedded processor" << endl; break;
  case EM_FIREPATH: 	 cout << "Element 14 64-bit DSP Processor" << endl; break;
  case EM_ZSP:       	 cout << "LSI Logic 16-bit DSP Processor" << endl; break;
  case EM_MMIX: 	 cout << "Donald Knuth's educational 64-bit processor" << endl; break;
  case EM_HUANY: 	 cout << "Harvard University machine-independent object files" << endl; break;
  case EM_PRISM:	 cout << "SiTera Prism" << endl; break;
  case EM_AVR:       	 cout << "Atmel AVR 8-bit microcontroller" << endl; break;
  case EM_FR30: 	 cout << "Fujitsu FR30" << endl; break;
  case EM_D10V: 	 cout << "Mitsubishi D10V" << endl; break;
  case EM_D30V: 	 cout << "Mitsubishi D30V" << endl; break;
  case EM_V850: 	 cout << "NEC v850" << endl; break;
  case EM_M32R: 	 cout << "Mitsubishi M32R" << endl; break;
  case EM_MN10300: 	 cout << "Matsushita MN10300" << endl; break;
  case EM_MN10200: 	 cout << "Matsushita MN10200" << endl; break;
  case EM_PJ:       	 cout << "picoJava" << endl; break;
  case EM_OPENRISC: 	 cout << "OpenRISC 32-bit embedded processor" << endl; break;
  case EM_ARC_COMPACT: 	 cout << "ARC International ARCompact processor (old spelling/synonym: EM_ARC_A5)" << endl; break;
  case EM_XTENSA: 	 cout << "Tensilica Xtensa Architecture" << endl; break;
  case EM_VIDEOCORE: 	 cout << "Alphamosaic VideoCore processor" << endl; break;
  case EM_TMM_GPP: 	 cout << "Thompson Multimedia General Purpose Processor" << endl; break;
  case EM_NS32K: 	 cout << "National Semiconductor 32000 series" << endl; break;
  case EM_TPC:       	 cout << "Tenor Network TPC processor" << endl; break;
  case EM_SNP1K: 	 cout << "Trebia SNP 1000 processor" << endl; break;
  case EM_ST200: 	 cout << "STMicroelectronics (www.st.com) ST200 microcontroller" << endl; break;
  case EM_IP2K: 	 cout << "Ubicom IP2xxx microcontroller family" << endl; break;
  case EM_MAX:       	 cout << "MAX Processor" << endl; break;
  case EM_CR:       	 cout << "National Semiconductor CompactRISC microprocessor" << endl; break;
  case EM_F2MC16: 	 cout << "Fujitsu F2MC16" << endl; break;
  case EM_MSP430: 	 cout << "Texas Instruments embedded microcontroller msp430" << endl; break;
  case EM_BLACKFIN: 	 cout << "Analog Devices Blackfin (DSP) processor" << endl; break;
  case EM_SE_C33: 	 cout << "S1C33 Family of Seiko Epson processors" << endl; break;
  case EM_SEP:       	 cout << "Sharp embedded microprocessor" << endl; break;
  case EM_ARCA: 	 cout << "Arca RISC Microprocessor" << endl; break;
  case EM_UNICORE: 	 cout << "Microprocessor series from PKU-Unity Ltd. and MPRC of Peking University" << endl; break;
  case EM_EXCESS: 	 cout << "eXcess: 16/32/64-bit configurable embedded CPU" << endl; break;
  case EM_DXP:       	 cout << "Icera Semiconductor Inc. Deep Execution Processor" << endl; break;
  case EM_ALTERA_NIOS2:  cout << "Altera Nios II soft-core processor" << endl; break;
  case EM_CRX:       	 cout << "National Semiconductor CompactRISC CRX microprocessor" << endl; break;
  case EM_XGATE: 	 cout << "Motorola XGATE embedded processor" << endl; break;
  case EM_C166: 	 cout << "Infineon C16x/XC16x processor" << endl; break;
  case EM_M16C: 	 cout << "Renesas M16C series microprocessors" << endl; break;
  case EM_DSPIC30F: 	 cout << "Microchip Technology dsPIC30F Digital Signal Controller" << endl; break;
  case EM_CE:       	 cout << "Freescale Communication Engine RISC core" << endl; break;
  case EM_M32C: 	 cout << "Renesas M32C series microprocessors" << endl; break;
  case EM_TSK3000: 	 cout << "Altium TSK3000 core" << endl; break;
  case EM_RS08: 	 cout << "Freescale RS08 embedded processor" << endl; break;
  case EM_SHARC: 	 cout << "Analog Devices SHARC family of 32-bit DSP processors" << endl; break;
  case EM_ECOG2: 	 cout << "Cyan Technology eCOG2 microprocessor" << endl; break;
  case EM_SCORE7: 	 cout << "Sunplus S+core7 RISC processor" << endl; break;
  case EM_DSP24: 	 cout << "New Japan Radio (NJR) 24-bit DSP Processor" << endl; break;
  case EM_VIDEOCORE3: 	 cout << "Broadcom VideoCore III processor" << endl; break;
  case EM_LATTICEMICO32: cout << "RISC processor for Lattice FPGA architecture" << endl; break;
  case EM_SE_C17: 	 cout << "Seiko Epson C17 family" << endl; break;
  case EM_TI_C6000: 	 cout << "The Texas Instruments TMS320C6000 DSP family" << endl; break;
  case EM_TI_C2000: 	 cout << "The Texas Instruments TMS320C2000 DSP family" << endl; break;
  case EM_TI_C5500: 	 cout << "The Texas Instruments TMS320C55x DSP family" << endl; break;
  case EM_TI_ARP32: 	 cout << "Texas Instruments Application Specific RISC Processor, 32bit fetch" << endl; break;
  case EM_TI_PRU: 	 cout << "Texas Instruments Programmable Realtime Unit" << endl; break;
  case EM_MMDSP_PLUS: 	 cout << "STMicroelectronics 64bit VLIW Data Signal Processor" << endl; break;
  case EM_CYPRESS_M8C: 	 cout << "Cypress M8C microprocessor" << endl; break;
  case EM_R32C: 	 cout << "Renesas R32C series microprocessors" << endl; break;
  case EM_TRIMEDIA: 	 cout << "NXP Semiconductors TriMedia architecture family" << endl; break;
  case EM_QDSP6: 	 cout << "QUALCOMM DSP6 Processor" << endl; break;
  case EM_8051: 	 cout << "Intel 8051 and variants" << endl; break;
  case EM_STXP7X: 	 cout << "STMicroelectronics STxP7x family of configurable and extensible RISC processors" << endl; break;
  case EM_NDS32: 	 cout << "Andes Technology compact code size embedded RISC processor family" << endl; break;
  case EM_ECOG1: 	 cout << "Cyan Technology eCOG1X family" << endl; break;
  case EM_MAXQ30: 	 cout << "Dallas Semiconductor MAXQ30 Core Micro-controllers" << endl; break;
  case EM_XIMO16: 	 cout << "New Japan Radio (NJR) 16-bit DSP Processor" << endl; break;
  case EM_MANIK: 	 cout << "M2000 Reconfigurable RISC Microprocessor" << endl; break;
  case EM_CRAYNV2: 	 cout << "Cray Inc. NV2 vector architecture" << endl; break;
  case EM_RX:       	 cout << "Renesas RX family" << endl; break;
  case EM_METAG: 	 cout << "Imagination Technologies META processor architecture" << endl; break;
  case EM_MCST_ELBRUS: 	 cout << "MCST Elbrus general purpose hardware architecture" << endl; break;
  case EM_ECOG16: 	 cout << "Cyan Technology eCOG16 family" << endl; break;
  case EM_CR16: 	 cout << "National Semiconductor CompactRISC CR16 16-bit microprocessor" << endl; break;
  case EM_ETPU: 	 cout << "Freescale Extended Time Processing Unit" << endl; break;
  case EM_SLE9X: 	 cout << "Infineon Technologies SLE9X core" << endl; break;
  case EM_L10M: 	 cout << "Intel L10M" << endl; break;
  case EM_K10M: 	 cout << "Intel K10M" << endl; break;
  case EM_AARCH64: 	 cout << "ARM 64-bit architecture (AARCH64)" << endl; break;
  case EM_AVR32: 	 cout << "Atmel Corporation 32-bit microprocessor family" << endl; break;
  case EM_STM8: 	 cout << "STMicroeletronics STM8 8-bit microcontroller" << endl; break;
  case EM_TILE64: 	 cout << "Tilera TILE64 multicore architecture family" << endl; break;
  case EM_TILEPRO: 	 cout << "Tilera TILEPro multicore architecture family" << endl; break;
  case EM_MICROBLAZE: 	 cout << "Xilinx MicroBlaze 32-bit RISC soft processor core" << endl; break;
  case EM_CUDA: 	 cout << "NVIDIA CUDA architecture" << endl; break;
  case EM_TILEGX: 	 cout << "Tilera TILE-Gx multicore architecture family" << endl; break;
  case EM_CLOUDSHIELD: 	 cout << "CloudShield architecture family" << endl; break;
  case EM_COREA_1ST: 	 cout << "KIPO-KAIST Core-A 1st generation processor family" << endl; break;
  case EM_COREA_2ND: 	 cout << "KIPO-KAIST Core-A 2nd generation processor family" << endl; break;
  case EM_ARC_COMPACT2:  cout << "Synopsys ARCompact V2" << endl; break;
  case EM_OPEN8: 	 cout << "Open8 8-bit RISC soft processor core" << endl; break;
  case EM_RL78: 	 cout << "Renesas RL78 family" << endl; break;
  case EM_VIDEOCORE5: 	 cout << "Broadcom VideoCore V processor" << endl; break;
  case EM_78KOR: 	 cout << "Renesas 78KOR family" << endl; break;
  case EM_56800EX: 	 cout << "Freescale 56800EX Digital Signal Controller (DSC)" << endl; break;
  case EM_BA1:       	 cout << "Beyond BA1 CPU architecture" << endl; break;
  case EM_BA2:       	 cout << "Beyond BA2 CPU architecture" << endl; break;
  case EM_XCORE: 	 cout << "XMOS xCORE processor family" << endl; break;
  case EM_MCHP_PIC: 	 cout << "Microchip 8-bit PIC(r) family" << endl; break;
  case EM_INTEL205: 	 cout << "Reserved by Intel" << endl; break;
  case EM_INTEL206: 	 cout << "Reserved by Intel" << endl; break;
  case EM_INTEL207: 	 cout << "Reserved by Intel" << endl; break;
  case EM_INTEL208: 	 cout << "Reserved by Intel" << endl; break;
  case EM_INTEL209: 	 cout << "Reserved by Intel" << endl; break;
  case EM_KM32: 	 cout << "KM211 KM32 32-bit processor" << endl; break;
  case EM_KMX32: 	 cout << "KM211 KMX32 32-bit processor" << endl; break;
  case EM_KMX16: 	 cout << "KM211 KMX16 16-bit processor" << endl; break;
  case EM_KMX8: 	 cout << "KM211 KMX8 8-bit processor" << endl; break;
  case EM_KVARC: 	 cout << "KM211 KVARC processor" << endl; break;
  case EM_CDP:       	 cout << "Paneve CDP architecture family" << endl; break;
  case EM_COGE: 	 cout << "Cognitive Smart Memory Processor" << endl; break;
  case EM_COOL: 	 cout << "Bluechip Systems CoolEngine" << endl; break;
  case EM_NORC: 	 cout << "Nanoradio Optimized RISC" << endl; break;
  case EM_CSR_KALIMBA: 	 cout << "CSR Kalimba architecture family" << endl; break;
  case EM_Z80:       	 cout << "Zilog Z80" << endl; break;
  case EM_VISIUM: 	 cout << "Controls and Data Services VISIUMcore processor" << endl; break;
  case EM_FT32: 	 cout << "FTDI Chip FT32 high performance 32-bit RISC architecture" << endl; break;
  case EM_MOXIE: 	 cout << "Moxie processor family" << endl; break;
  case EM_AMDGPU: 	 cout << "AMD GPU architecture	" << endl; break;
  case EM_RISCV: 	 cout << "RISC-V" << endl; break;
  default:
    cout << "Reserved/Unrecognized" << endl;
    break;
  }
  return true;

}

bool getFileFormatVersion(char* buffer)
{
  cout << "Object file version: ";
  unsigned long long value;
  value = getValue(buffer, getSize(ELF_WORD));
  E_VERSION = value;
  switch (E_VERSION) {
  case EV_NONE:
    cout << "Invalid version" << endl;
    return false;
  default:
    cout << E_VERSION << endl;
  }
  return true;
}

bool getEntryPointAddress(char* buffer)
{
  cout << "Entry point address: ";
  unsigned long long value;
  value = getValue(buffer, getSize(ELF_ADDR));
  E_ENTRY = value;
  if (E_ENTRY == 0)
    cout << "No associated entry point" << endl;
  else
    cout << "0x" << hex << E_ENTRY << endl;
  return true;
}

bool getProgramHeaderTableOffset(char* buffer)
{
  cout << "Program header table's offset: ";
  unsigned long long value;
  value = getValue(buffer, getSize(ELF_OFF));
  E_PHOFF = value;
  if (E_PHOFF == 0) {
    cout << "No program header table" << endl;
    programHeaderTable = nullptr;
  }
  else {
    cout << "0x" << hex << E_PHOFF << endl;
    programHeaderTable = beginning + E_PHOFF;
  }
  return true;
}

bool getSectionHeaderTableOffset(char* buffer)
{
  cout << "Section header table's offset: ";
  unsigned long long value;
  value = getValue(buffer, getSize(ELF_OFF));
  E_SHOFF = value;
  if (E_SHOFF == 0) {
    cout << "No section header table" << endl;
    sectionHeaderTable = nullptr;
  }
  else {
    cout << "0x" << hex << E_SHOFF << endl;
    sectionHeaderTable = beginning + E_SHOFF;
  }
  return true;
}

bool getFlags(char* buffer)
{
  cout << "Processor specific flags: 0x";
  unsigned long long value;
  value = getValue(buffer, getSize(ELF_WORD));
  E_FLAGS = value;
  cout << hex << value << endl;
  return true;
}

bool getElfHeaderSize(char* buffer)
{
  cout << "ELF header's size: 0x";
  unsigned long long value;
  value = getValue(buffer, getSize(ELF_HALF));
  E_EHSIZE = value;
  cout << hex << value << " (" << dec << value << ")" << endl;
  return true;
}

bool getProgramHeaderEntrySize(char* buffer)
{
  cout << "Size of program header table entry: 0x";
  unsigned long long value;
  value = getValue(buffer, getSize(ELF_HALF));
  E_PHENTSIZE = value;
  cout << hex << value << " (" << dec << value << ")" << endl;
  return true;
}

bool getProgramHeaderEntriesNumber(char* buffer)
{
  cout << "Number of entries in program header table: 0x";
  unsigned long long value;
  value = getValue(buffer, getSize(ELF_HALF));
  E_PHNUM = value;
  cout << hex << value << " (" << dec << value << ")" << endl;
  return true;
}

bool getSectionHeaderEntrySize(char* buffer)
{
  cout << "Size of section header table entry: 0x";
  unsigned long long value;
  value = getValue(buffer, getSize(ELF_HALF));
  E_SHENTSIZE = value;
  cout << hex << value << " (" << dec << value << ")" << endl;
  return true;
}

bool getSectionHeaderEntriesNumber(char* buffer)
{
  cout << "Number of entries in section header table: 0x";
  unsigned long long value;
  value = getValue(buffer, getSize(ELF_HALF));
  if (value == 0) {
    value = getSectionHeaderEntryField(0, SH_FIELD_SIZE);
  }
  E_SHNUM = value;
  cout << hex << value << " (" << dec << value << ")" << endl;
  return true;
}

unsigned long long getSectionHeaderEntryField(unsigned long long sectionID, int fieldID)
{
  unsigned long long offset = 0;

  // for a field ID add sizes of each field before
  for (int i = fieldID; i > 0; i--)
    offset += getSectionHeaderFieldSize(i-1);
  
  unsigned long long totalOffset;
  totalOffset = sectionID * E_SHENTSIZE + offset;

  char* buffer;
  buffer = sectionHeaderTable + totalOffset;

  unsigned long long value = getValue(buffer, getSectionHeaderFieldSize(fieldID));
  cout << hex << value << dec << " " ;
  
  return value;
}

int getSectionHeaderFieldSize(int fieldID)
{
  switch (fieldID) {
  case SH_FIELD_ENTSIZE:
    return getSize(ELF_XWORD);
  case SH_FIELD_ADDRALIGN:
    return getSize(ELF_XWORD);
  case SH_FIELD_INFO:
    return getSize(ELF_WORD);
  case SH_FIELD_LINK:
    return getSize(ELF_WORD);
  case SH_FIELD_SIZE:
    return getSize(ELF_XWORD);
  case SH_FIELD_OFFSET:
    return getSize(ELF_OFF);
  case SH_FIELD_ADDR:
    return getSize(ELF_ADDR);
  case SH_FIELD_FLAGS:
    return getSize(ELF_XWORD);
  case SH_FIELD_TYPE:
    return getSize(ELF_WORD);
  case SH_FIELD_NAME:
    return getSize(ELF_WORD);
  }
  return 0;
}

bool getNameStringTableIndex(char* buffer)
{
  cout << "Section ID of section name string table: ";
  unsigned long long value;
  value = getValue(buffer, getSize(ELF_HALF));
  if (value == SHN_XINDEX)
    value = getSectionHeaderEntryField(0, SH_FIELD_LINK);
  E_SHSTRNDX = value;
  if (value == SHN_UNDEF) {
    cout << "No such section" << endl;
    return true;
  }
  cout << "0x" << hex << value << " (" << dec << value << ")" << endl;
  return true;
}
