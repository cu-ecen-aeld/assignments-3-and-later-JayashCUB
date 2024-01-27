Compiler := gcc

ifeq ($(CROSS_COMPILE),aarch64-none-linux-gnu-)
	Compiler := aarch64-none-linux-gnu-gcc
endif

writer: writer.o
	$(Compiler) writer.o -o writer
	
writer.o: writer.c
	$(Compiler) -c writer.c
	
clean:
	rm -f *.o writer
