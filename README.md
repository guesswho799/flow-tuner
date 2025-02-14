# FlowTuner
*Tunes Function ordering in an elf binary to achive better `instruction cache` utilization*

## Contents

 * [Function order explanation](#function-order-explanation)
 * [Algorithm explanation](#algorithm-explanation)
 * [Branch prediction showcase](#branch-prediction-showcase)
 * [Removes dead code](#removes-dead-code)
 * [How to build](#how-to-build)
 * [Dependencies](#dependencies)

## Function order explanation

Given 10 functions, each sized 6 bytes and a cache line of 5 bytes.<br>
Running a single function will cause 2 icache misses, one for the first 5 bytes and the second for the last byte.<br>
Using the default random function placement we get 20 icache misses for running these 10 functions.<br>
But lets say these 10 functions are placed one after another, the new icache miss count goes down to 12 from 20.<br>
![TuneFlow](https://github.com/user-attachments/assets/28bcec54-2e91-41d8-a7a3-fc8cdcbf4d5c)


## Algorithm explanation

- Iterate text section symbols, mapping symbols to their dependency
- Iterate dependency map popping dependency chains in execution order
- Resolving addresses according to new placement
- Write out text section using popping order

## Branch prediction showcase

But functions call more than one function, we order functions based on the first dependency.<br>
What if the first symbol the function calls is in a very unlikely branch (e.g. asserting on null argument).<br>
Luckly, gcc is very good at branch predictions and places the most likely branch first.<br>
Here is a simplified output of two compilations, one predicting exit and one predicting sleep.<br>
```c
if (rand() != 0) [[un/likely]]
    exit(1);
else
    sleep(1);
```
| Likely  | Unlikely |
| ------------- | ------------- |
| call   rand  | call   rand  |
| test   eax, eax  | test   eax, eax  |
| je     skip exit  | jne    skip sleep  |
| call   exit  | call   sleep  |
| call   sleep  | call   exit  |

## Removes dead code

When compiling with Gcc and Clang a static binary,<br>
the compilers look at the binary's library dependencies and just copy pastes the whole library to the final binary.<br>
Meaning that if your code uses a single standalone function from a giant library, you will pay for more than you use.<br>
FlowTuner reorders functions in the order they are used hence unused functions are omitted, resulting in a leaner executable.<br>

## How to build

```console
gcc -static -O3 test/main.c -o test/program
mkdir build && cd build
cmake .. && make -j16
./FlowTuner -i ../test/program -o outbinary
```

## Dependencies
* Capstone for disassembling
* cxxopt for cli argument parsing
