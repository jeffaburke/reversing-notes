# Aligning the Stack through `gdb`
`gdb` by default passes in extra parameters into the environment which isn't a problem for current reversing problems but this can be a problem later when it comes to bit-precise exploit code. Here we learn how to synchronize the environment.
Running the program plainly:
![](Attachments/Pasted%20image%2020260827161421.png)
Running the program under `gdb`:
![](Attachments/Pasted%20image%2020260827161510.png)

We can subtract `0x83` from `0x2e` we get the difference of `85` in decimal. We can take that into a simple python script to get our output accounting for python loops funkiness (hindsight I think this might be the extra null byte that gets added to the environment variable string) and the four letters of the environment variable declaration. 
![](Attachments/Pasted%20image%2020260827161521.png)
Appending our new environment variable to the start of the program gives us the flag.
![](Attachments/Pasted%20image%2020260827161530.png)
# Aligning the Stack Through `gdb`, Generalized
In the real world the differences in the stack may be a bit more obscure/larger than the example from above, differing between target and my local setup. If the binary was run as a `cron` job or remote script or service is may have a completely different environment. We can use `env -i` to pass in a clean environment and set environment variables there before running with `gdb`.

Running the program by itself I see that it wants 1 environment variable.
![](Attachments/Pasted%20image%2020260827161536.png)
Next we open it and run it with `gdb` and see what we need to get our environment to match.
![](Attachments/Pasted%20image%2020260827161541.png)
We then use `env -i` to run the program with a new environment passing the one variable it asked for.
![](Attachments/Pasted%20image%2020260827161555.png)
We then use our python methodology to do this once again. 
![](Attachments/Pasted%20image%2020260827161600.png)
Adding onto our original environment variable the extra characters we get the following.
![](Attachments/Pasted%20image%2020260827161649.png)
