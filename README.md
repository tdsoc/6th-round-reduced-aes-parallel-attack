6th-round-reduced-aes-parallel-attack
=====================================

The Partial Sum Attack on 6-round reduced AES, parallel version

This is the parallel version of the code provided in the
6th-round-reduced-aes-attack repository.

It is not perfect and there is some redundant code, but it is fast.
Really fast.

To run it you need to use a storage shared between every node (NFSv4 works well)
and OpenMPI, to compile and run the code (both the binary and the header files).

To compile it:
mpicc -O3 attack_functions.c cipher.c utility.c aes_smasher.c -o /aes-smasher/aes-smasher

Be carefull, the produced binary must be present, and in the same path, on every node.

Create also an host file (see the OpenMPI documentation to understand how), and then run
the attack as follow (25 is an example, use the number of workers you want):
mpirun --verbose --hostfile aes_hosts -n 25 /aes-smasher/aes-smasher 2>&1 | tee /aes-smasher/attack.log

Due to the nature of the attack, it takes a while to complete (even if it is really really fast),
so using screen would be a good idea.
