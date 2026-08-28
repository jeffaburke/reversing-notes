# Robert's GDB Walkthrough
This is a video with a simple C program being run through GDB. Here Robert walks through various commands/shorthand's which would be useful to know when using GDB. 

Commands at a high level:
- `run`/`r`: Runs the program till a breakpoint is hit or the program exits. The program arguments can be followed by this command.
- `starti`: Starts the program loading the first instruction to run then stops. Like `run` this can also take the program arguments.
- `stepi`/`si`: Step instruction the amount of instruction to step can be specified.
- `nexti`/`ni`: Next instruction, step over the instruction.
- `break *<func name>`/`b`: Break at the point where this function is started. Takes a pointer.
	- Can be passed memory locations although this isn't the best in practice as memory addresses change.
	- `*<func name> + <offset>`: Will break at the location of an instruction with the given offset
- `print`/`p`: Print the given value. It will saved the value that is print out in a variable which can be used later.
	- Registers can be passed with `$<reg name>`
	- Options are the same as `x`.
	- Type casting can be passed in as well
		- For example `p/a *(long *) $rsp` will grab the value at `rsp` cast it as a `long` integer then dereference that value
- `disassemble`/`disass`: Disassemble the given chunk of code
	- Optional: Function name/address to disassemble
- `info`
	- `register`/`reg`: Will output the register values
- `x`: Examine/dereference the value given to it.
	- Optional `<n>`: Amount of lines to examine.
	- `i`: Get the instruction at the location examined.
	- `gx`: Giant Hex
	- `x`: Hex
	- `d`: Signed numbers
	- `u`: Unsigned numbers
	- `a`: Address
- `printf`: Can be used to output values like in C syntax
	- For example `printf "%lx\n, $5` will grab the long integer stored in `$5` and output it to the terminal.
- `display`: Similar to `print` (same options can be passed) but it will run after a step/next command.
	- For example `display/4i $rip` will display the next 4 instructions after a command
- `finish`: Run till the end of the program avoid breaks #TODO check command
- `continue`/`c`: Run till next break
- `set $<var name> = <value>`: Set the value (can be a register/other variable) of a variable
	- Values and variables can be type cast in the same way they were with print
Not discussed in the video at least as of where I am right now:
- `set disassembly-flavor intel`: Don't like AMD :p
	- This can be set `.gdbinit`

`gdb` can be passed scripts.
- These script files take the same format as if we were running `gdb` commands individually. The language also supports conditionals. The syntax used is `commands` and `end` to end the command block is the last command was run properly.
- One example of this would be if a breakpoint is hit.
  ```
  b *main
  commands
	  silent
	  p/a $rip
  end
  ```