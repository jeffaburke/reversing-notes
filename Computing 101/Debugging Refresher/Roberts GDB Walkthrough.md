# Robert's GDB Walkthrough
This is a video with a simple C program being run through GDB. Here Robert walks through various commands/shorthand's which would be useful to know when using GDB. 

Commands at a high level:
- `run`/`r`: Runs the program till a breakpoint is hit or the program exits. The program arguments can be followed by this command.
- `starti`: Starts the program loading the first instruction to run then stops. Like `run` this can also take the program arguments.
- `stepi`/`si`: Step instruction the amount of instruction to step can be specified.
- `break *<func name>`: Break at the point where this function is started.
- `print`/`p`: Print the given value. It will saved the value that is print out in a variable which can be used later.
	- Registers can be passed with `$<reg name>`
	- #TODO add the important options that can be given to this.
- `disass`: Disassemble the given chunk of code
	- For example a function name can be passed in
- 

Not discussed in the video at least as of where I am right now:
- `set disassembly-flavor intel`: Don't like AMD :p