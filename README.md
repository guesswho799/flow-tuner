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

Given a function 6 bytes long and a cache line of 5 bytes.<br>
Running it will cause 2 icache misses, one for the first 5 bytes and the second for the last byte.<br>
Now imagine 10 functions,<br>
Using the default random function placement we get 20 icache misses for running these 10 functions.<br>
But if these 10 functions were placed one after another, the new icache miss count whould go down from 20 to 12.<br>
![TuneFlow](https://github.com/user-attachments/assets/28bcec54-2e91-41d8-a7a3-fc8cdcbf4d5c)<br>
This optimization would work better as an adaptive optimization, implemented in a jit compiler.<br>
The compiler could count function calls,then reorder them at runtime acording to the hotest path.



## Algorithm explanation

- Map functions to the functions they call
- Reorder functions to execution order, starting from entry point
- Update text section to new function order
- Update new function address anywhere else (symbol table, plt, jump tables, etc)

## Branch prediction showcase

But functions call more than one function, we order functions based on the first dependency.<br>
What if the first symbol the function calls is in a very unlikely branch (e.g. asserting on null argument).<br>
Luckly, gcc is very good at branch predictions and places the most likely branch first.<br>
Here is a simplified output of two compilations, one predicting exit and one predicting sleep.<br>
```c
if (rand()) [[un/likely]]
    exit(0);
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
./FlowTuner -i ../test/program -o a.out
```

## Dependencies
* Capstone for disassembling
* cxxopt for cli argument parsing
