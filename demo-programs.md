# Incrementing
Increment rbx 10 times in a loop, using rax as a counter:

```
emulate B80A00000083C30183E80175F806 -r RBX=...
```

# Fibonacci
Compute the nth fibonacci number, where rax = N.

```
emulate 50E80100000006488B4424084883F80272214883E80150E8EBFFFFFF488704244883E80150E8DDFFFFFF48034424084883C410C3 -m '5000=4096*00' -r RSP=6000 -r RAX=4y
```