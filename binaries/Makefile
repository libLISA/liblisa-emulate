all: hello-world.elf hello-world-c.elf mystery.elf

%.o: %.s
	nasm -f elf64 $<

%.elf: %.c
	gcc $< -o $@

%.elf: %.o
	ld $< -o $@

mystery.elf: mystery.c
	gcc -fno-inline -O3 mystery.c -o $@ && strip $@
