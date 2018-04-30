CPPFLAGS=--std=c++14

analyzer: analyzer.o elf.o
	g++ -o analyzer analyzer.o elf.o 

analyzer.o: analyzer.cpp
	g++ $(CPPFLAGS) -c analyzer.cpp

elf.o: elf.cpp elf.h elfFlags.h
	g++ $(CPPFLAGS) -c elf.cpp

clear:
	rm *.o
