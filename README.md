# FlowTuner
*Tunes Function ordering in an elf binary to achive better `instruction cache` utilization*

### Roadmap
- iterate text section symbols, grouping symbols by dependency
	- map<Dependent, Dependencies>
- iterate dependency map calculating score to each dependent
	- dependent calling dependency many times or in loop
	- think of more things to take into account...
- iterate dependency map popping highest scoring dependency chain
	- add score by sum size of symbols mod to cache line size
		- taking into account previous sum
	- each pop includes removing dependent from remaining vectors
- write out text section using popping order
	- taking new addresses in account
tests:
- perf stat -e L1-icache-loads,L1-icache-misses ./outbinary
- calculate average of diff between symbol dependency

## How to build
```console
gcc -static test/main.c -o test/program
mkdir build && cd build
cmake .. && make -j16
./FlowTuner -i ../test/program -o outbinary
```

### Dependencies
* Capstone for disassembling
* cxxopt for cli argument parsing
