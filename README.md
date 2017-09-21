# ProXBBE (Protocol Extraction By Binary Execution)

ProXBBE utilizes dynamic binary analysis in order to infer field boundaries of received network messages and, to some extend, their semantics.
This is a student project I did a while a go at the Institute of Distributed Systems, University of Ulm.
This software is of PoC-quality - don't expect it to run smoothly (feel free to open issues/PRs, though).
The goal was to implement methods, proposed by the [Polyglot research paper](http://bitblaze.cs.berkeley.edu/papers/polyglot_ccs07_av.pdf)(pdf), one of the first papers dealing with this topic.
Hence, the project is build around the idea, presented in that paper.

The project has a C++ tracer for GNU/Linux x86_64, built on top of PIN and a from-scratch written tainting engine with the corresponding analysis routines, written in Ruby.
The only requirements are the package build-essential, G++ (compiler), a Ruby interpreter and the PIN framework.
My impression was the existing taint engines, like Triton, having a lot of heavy dependencies on third-party libraries.
I thought it would be easy to write one from-scratch.
Turns out I was wrong - ended up putting a lot of overtime into tainting routines.
Besides me learning a lot, the result was a pretty slick and hackable tainting engine.
In the following sections I'll give an introduction into the project and its usage.
If you want to understand the internals or want to dig through the source code, I heavily suggest you read chapters 5-7 of the [project documentation](https://msgpeek.net/static/proxbbe_projectdoc.pdf)(pdf).

## Up Front - Stuff That Doesn't Work

There are some glitches I couldn't solve until the project deadline and mistakes I found in retrospect.
Inference of delimited fields work pretty well.
Keyword field inference should start working properly as soon as support for SIMD-Extensions is implemented (see Limitations 5.).
The implementation of keywords is pretty simple and I verified through digging in the traces, that string compares utilize these extensions. At the moment it finds only few of the keywords (when if-compares are used byte-wise).
Inference of fixed-length fields works good - some inaccuracies could be probably owned to mishandling of MOVXZ instructions (see Limitations 3.).
Direction(length) field inference is deactivated, although implemented, since it produces a lot of false-positives. One explanation are the wrong taint policy and mishandling of MOVXZ instructions (see Limitations 4. and 5.).
This will improve after fixing these issues, but I am not sure if it will get much better. At this point, the Polyglot paper doesn't provide much details on the methodology or I misunderstand what the authors mean.
The counter-direction (counter fields of fixed length fields, e.g., record pointers in DNS) fields, work properly, but their targets are not inferred correctly (no idea what causes that, yet).

I plan to fix the issues listed below. At the moment, this will have to wait a couple of months in favor of another project.

## Project Description

ProXBBE traces an executed binary and records all instructions, along with the corresponding CPU State, i.e. register values.
As soon as a syscall is executed, which is responsible for receiving network traffic, its parameters and return value are recorded and saved in the execution trace.
This makes it possible to determine where the network message was copied to, to be more specific the memory address and size of the message.

Later, a second tool, the analyzer, takes the trace as input.
The recorded syscalls determine the buffers with relevant messages.
We taint the memory areas, as soon as they appear in the traces.
Tainting, often referred to as Dynamic Flow Tracking (DFT), means we mark a memory area of interest and track accesses to that area.
One has also to ensure, that when data copied from tainted areas, the destination is marked accordingly (Taint Spreading).
Ruby and Perl have [built-in support for DFT](https://en.wikipedia.org/wiki/Taint_checking).
One can retrieve the status of a variable to determine whether it's tainted or not.
This mechanism can be used to track untrusted data across the application and detect its usage, e.g, for SQLi detection or when tainted data find its way into the Program Counter, which heavily suggests a buffer overrun.
While a simple implementation presents "taint" in a binary way (tainted or not), other use cases require more information.
To determine field boundaries the Taint Engine must contain offset information of the network message for every memory access.
For example, if a successful comparison at the seventh byte of the network message happens against a one byte long static value, one could assume the byte at position seven represents a field (that's an oversimplified example).

Making assumptions about how network protocols are parsed, ProXBBE analyzes memory access to the packets to infer field boundaries and their (rough) semantics.
In the following I'll give a very short description on how ProXBBE determines field boundaries and their semantics.
Again, if you want more details I'd like to refer you to the project documentation, linked above.

#### Delimiters and Delimited fields

Delimiters are one or multiple bytes which segregate fields of variable length.
The assumption behind the inference approach is that the message is compared byte by byte against a fixed value.
All unsuccessful comparisons against a consecutive byte sequence state a field, which is in scope of a delimiter.
The first successful compare determines the delimiter byte.
If the following compared byte or bytes yield yet another successful compare, the delimiter is extended by this byte(s).
The intuition is the target program will compare bytes at offset 0 to 15 to the constant value "\\r".
The comparison at offset 15, in contrast to the ones before, is successful.
Therefore, we conclude bytes 0-14 are delimited by the delimiter "\\r".
When consecutive successful comparisons follow, the delimiter is extended by this bytes.
The maximum length of a delimiter is limited to four, with the rationale delimiters tend to be short.

![Delimiter Example](doc/delimiter_consecutive_bytes2.png?raw=true "Delimiter Example")

#### Keyword Fields

Keyword fields consist of bytes known to the target program, beforehand.
These are fixed byte-values the network message is compared against.
This work follows Polyglot's intuition that keywords can be found by extracting true comparisons.
Therefore, this inference phase reuses the compare-instructions, extracted during delimiter inference.
All true compare-instructions are considered as part of a keyword.
Subsequent true-comparisons are considered as one keyword.
As soon as an address does not yield such a comparison, a keyword is closed.
A further constrain is that keywords cannot contain already inferred delimiters.

#### Direction/Length and Their Target  Fields

Direction fields relate to other fields inside the same message.
In most cases these are length fields used to calculate pointers of other variable-length fields, so called target fields.
A direction field can be determined as soon as its value is used as an offset for another field.
This field is not the corresponding target field but the following.
We collect all instructions which access a tainted memory area and at the same time use a tainted base or index register to calculate the address.
The value from the tainted base/index register is considered as direction field, and the resulting destination memory address as the beginning of the field after the target.
We conclude that the end of the desired target field is one byte earlier.
Still, we can not conclude the address of its beginning.
Therefore, we temporarily assume the beginning to be one byte after the direction field's end.
We change this assumption as soon as any other field was found during other inference stages.
If multiple targets have been found, the smaller address is used.

![Direction and Target Example](doc/direction_target_example.png?raw=true "Direction and Target Example")

#### Direction/Counter and Their Target  Fields

It is possible the pointer increment is done by a constant value inside a loop, and therefore, is not tainted.
In order to find these fields all loops with a tainted stop condition, i.e. compares with one tainted operand, are extracted.
This operand is considered as direction field, and message fields without a tainted base or index accessed within the loop are considered as direction field.
This pattern is often found when the target field has a fix length and the direction is a counter for the amount of records, e.g., DNS.

#### Fix-Length Fields

Fixed-length fields are fields that are used by an application at a time.
For their detection ProXBBE collects all tainted accesses to the received message.
Every access on a memory range is considered as an fixed-length field.
As soon as memory accesses occur on overlapping ranges, these are merged together.
Due to architecture-based restrictions (64-bit CPU) an application can access a maximum of eight bytes at a time.
However, since most protocols were designed with portability in mind, it is more likely their maximum field lengths are 4 byte long.
Since, previous inference phases already determined variable-length fields, we exclude these memory area from the list of fixed-length fields.

## Tracer

[Intel PIN](https://software.intel.com/en-us/articles/pin-a-binary-instrumentation-tool-downloads) is an dynamic binary instrumentation (DBI) framework/tool.
It rewrites a binary's code during runtime in order to inject analysis routines.
It offers a rich API to determine when callbacks to a certain analysis logic should be taken, and gives the analyst the ability to define what to do with the information.

ProXBBE defines callbacks before, after syscalls and before every executed instruction.
As soon as as syscall, related to receiving network messages, is called, the corresponding parameters and its return value are saved into the trace.
As soon as the first relevant syscall was recorded, ProXBBE starts recording executed instructions, along with values of the GPRs and further information about the instruction.
The resulting execution trace is output as a file in [JSON Lines](http://jsonlines.org/) format, which in return will be used as input by ProXBBE's Analyzer, later.

The analysis routines are inserted into each process separately.
Since, it is possible that multiple threads participate in network communication, e.g., one reads network messages and another one parses it, ProXBBE's Tracer registers every network syscall for all threads.
This leads to false positives, i.e some recorded threads do no parsing of packets.
However, this is the only way to catch cases with distributed duties (one reads network traffic, another one parses it).

#### Build

The requirements for compiling the Tracer is Make and the G++(gcc) compiler.
On Debian-based Distributions the packages ``build-essential`` and ``g++`` are sufficient.
Next, [download PIN](https://software.intel.com/en-us/articles/pin-a-binary-instrumentation-tool-downloads) version 3.2, Kit 81205 and extract it.
Set the needed variables and compile the Analyzer.

```bash
wget https://software.intel.com/sites/landingpage/pintool/downloads/pin-3.2-81205-gcc-linux.tar.gz
tar xfz pin-3.2-81205-gcc-linux.tar.gz
# Include PIN into your PATH
export PATH=$PATH:/pathto/pin-3.2-81205-gcc-linux
export PATH=$PATH:/pathto/pin-3.2-81205-gcc-linux/source/include/pin
# Set PIN_ROOT variable
export PIN_ROOT=/pathto/pin-3.2-81205-gcc-linux
# Clone the project and compile
git clone https://github.com/msgpeek/proxbbe.git
cd proxbbe/tracer
make
```

#### Usage

The result is a "Pintool", which can be invoked in the following manner.

```bash
pin -t /pathto/proxbbe/tracer/obj-intel64/proxbbe_tracer.so -- /usr/bin/wget http://json.org
```

* ``pin`` is the executable of PIN, which should be in your PATH by now.
* ``-t`` is the cmdline switch to include a specific Pintool
* ``proxbbe_tracer.so`` is the Tracer Pintool
* ``--`` is a separator between PIN and its options and your target. Everything following is your target binary and its arguments.

PIN creates a file named *pintool.log* after every run.
The ProXBBE Tracers creates a lot of debug logs.
If somethings going wrong, you should have a look at it.
The actual results is saved in the file(s) with the naming schema *trace_output--pid\$PID-tid\$THREADID.jsonl*.
This file is created for every unique thread.

The file has two different entry types, syscalls with "type:0" for an InstructionState and "type:1" for SyscallStates.

```json
{
    "type":1,
    "ip":"7f32787e832e",
    "buf_addr":139854702575616,
    "buf_size":4096,
    "count":14,
    "flags":0,
    "msg":"MjIxIEdvb2RieWUuDQo="
}
{
    "type":0,
    "ip":"7f32787735b0",
    "mn_type":"BINARY",
    "iclass":"99",
    "instruction":"cmp rax, 0x0",
    "op_access": [
        {"rr":["rax",8]},
        {"imm":[0,1]},
        {"rw":["rflags",8]}
     ],
    "regs":
    {"rip":139854746170800,"rdi":4,"rsi":139854702575616, [...], "r14":0,"r15":0,"flags":515}
}
```

#### Predefine Socket descriptors

Sometimes, protocol implementations process network communication not only in different threads, like discussed, but also inside different processes.
This stays a limitation of the DBI-approach.
Some programming patterns like Prefork, create sockets in one process and inherit them to children.
For read() functions ProXBBE keeps a list of currently opened sockets.
Otherwise, there's no way to know whether it's a file descriptor or socket.
To work around this limitation the Tracer accepts the cmdline switch ``-fds``.


```bash
pin -t /pathto/proxbbe/tracer/obj-intel64/proxbbe_tracer.so -fds 3,4,42 -- /usr/bin/wget http://json.org
```

Even though it is not guaranteed the file/socket descriptors stay the same throughout executions, the often do.
This enables you to pass predefined socket descriptors in case the read() and open() functions happen in different processes (or pass 0 to look at stdin).

Note: Check the *pintool.log* for socket/file descriptor numbers.

#### Attach to Running Process

The Tracer records instructions as soon as the first network message was received and saves the whole execution Trace into memory, and when the process is finished writes it out to a file.
The execution traces vary between dozens of megabytes(wget) and multiple gigs (irssi).
When your target is a browser, I tried links, 30 gigs RAM are not enough.
You can attach PIN with the ``-pid`` cmdline switch to a running process short before the relevant message is received, in order to focus your trace on the relevant analysis.

```bash
pin -t /pathto/proxbbe/tracer/obj-intel64/proxbbe_tracer.so -pid 22124 -- /usr/bin/wget http://json.org
```

Note: [Ptrace support](https://www.kernel.org/doc/Documentation/security/Yama.txt) must be activated.
When you attach PIN to a running process, the trace will always be written into its current working directory.
E.g., Apache-HTTPD usually runs somewhere in /var/lib/.


## Analyzer

The Analyzer has no dependencies, except the Ruby runtime, of course.
It is well tested with Ruby version 2.4, but should also run on 2.3 and 2.2.
For small traces up to several hundreds of MB, it needs 1-2 minutes.
My record was about 15 minutes for multiple gigabytes.
It should be noted that size alone is a bad measurement - some traces "parse a lot".
Since, the traces are read in non-slurpy way, memory consumption stays moderate: 100-200MB.
I found that using JRuby (not well tested) speeds up things a bit, for big traces.

#### Usage

The Analyzer expects an execution trace from previous step as an argument.

```bash
./proxbbe_analyzer.rb trace_output--pid22711-tid0.jsonl
```

It gives you a colorful output with inference results.
If the buffer of your terminal emulator to scroll up is limited, you can look it up in the produced output file, with the extension .proxbbe, e.g., trace_output--pid22711-tid0.proxbbe.
Additionally, there's a log file (same file name, but with .log extension), which contains a lot of information about the decisions, made by the Analyzer.
In debug mode (default), all processed instructions and the current taint state (shadow memory and tainted registers), are logged.

![Partial Output of NGINX Analysis](doc/analyzer_output_example.png?raw=true "Partial Output of NGINX Analysis")

Output symbology:

X is a placeholder for an incremented number. Letters, followed by the same same number state bytes, which belong to one field.

* **dX** stands for delimited byte. A capital **DX** is the corresponding delimiter.
* **KX** stands for keyword.
* **DIX** stands for direction(length), the corresponding target fields are marked as **TAX**
* **COX** stands for direction(counter), the corresponding target fields are marked as **TCX**
* **FXX** stands for a Fix-Length field.
* If no field could be inferred, it's highly likely that the implementation did not access the particular byte.

#### Buffered Reading Detection

The Tracer records all received messages in bulk.
For example, if you use wget, this will include DNS responses.
Your actual target messages could be fetched during buffered reading in a loop.
ProXBBE tries to detect buffered reading respectively use of the (annoying) MSG_PEEK flag (see man 2 recv) to summarize traffic receptions into one message, if they belong together.
If you find this feature working not correctly for your target, you can use the ``--no-buf-read`` cmdline switch to interpret every syscall as one message.

## Limitations/open TODOs

1. ~~At the moment the operand values are parsed multiple times during Taint Spreading and different analysis routines. This originated through iterative addition of features. Rewrite the parsing of the operands and create a central "InstructionState" class, which offers access to operands and taint information.~~
2. ~~Exclude MOVs from fixlen-field field inference. The [Tupni paper](https://www.microsoft.com/en-us/research/wp-content/uploads/2016/02/tupni-ccs08.pdf)(pdf) has a good point about their meaning: ``We ignore move instructions as they do not process the operand and contain little information about field sizes.``~~
3. Implement correct handling of MOVXZ instructions. Through implementation of 2.) the negative effect of mishandling this instruction has been lowered on the fixed-length instructions. Still, the Taint Spreading doesn't work correctly. It should clear all registers parts, that are zeroed out and only taint the few destination bytes. This case must be handles in a special manner, but is doable in couple of hours. The negative effects are also seen in loop bodies, where MOVZX is a common habitant.
4. Rewrite the Taint Policy for Composite Destinations. At the moment a Union of labels, e.g., for *add* does an binary OR on the taint labels. When I was writing it, it kinda made sense. But looking at PANDA, I realize that my approach introduces accuracy issues. It makes more sense to have an array with labels and adding unionized labels to it. This is a much better approach, however this opens the question on how to interpret base and index registers with multiple labels, during direction field inference. What is the correct action for all other inference phases which handle operands with multiple labels?
5. Implement Streaming SIMD-Exetensions. Executing ``readelf -s /lib/libc.a | grep strncacecmp`` reveals that modern glibc implementation have multiple versions of each string handling and copy methods. During eval I saw that this is actively used in my traces and messes up Taint Spreading, as soon as any variation of strcmp() were involved. SSE is part of the x86_64 ABI and one can be certain that every 64bit CPU has built-in support for those. If you try to turn it off with compiler flags, the compiler process fails. It seems, their support is required for 64bit.
6. The file *code/analyzer/utils/pin_iclass.rb* contains a mapping of PIN instructions, which varies throughout PIN-releases. At the moment it is partly created by "intelligent grep-ing" and partly by hand. Writing a hacky script to automate this task, would make porting to newer versions easier.

## Roadmap

The issues listed above will be fixed. However, I am quite busy these days, so it will have to wait a couple of months.
The project is published here because I hoped somebody will find it useful to have some code to dig through while reading the papers of this topic (since, to my knowledge nobody published it).
Besides, the Tracer and the Taint Engine can be reused for any (remotely) related task.
I am looking forward to feedback.
Happy hacking.

## Licence

The copyright for the files base64.{h,cpp} is held by Rene Nyffenegger.
The files contain the (permissive) license.

The rest of this project ist published under the MIT license.

## Attribution

* The "Polyglot: Automatic Extraction of Protocol Message Format using Dynamic Binary Analysis" research by Juan Caballero, Heng Yin, Zhenkai Liang, and Dawn Song. Published  "In Proceedings of the 14th ACM Conference on Computer and Communications Security (CCS), October 2007". ProXBBE is based on their ideas.
* I found the paper and the source code of [Libdft](https://www.cs.columbia.edu/~vpk/research/libdft/) very useful for understanding DFT. I actively dug through their source, while I was implementing my Taint Engine.
* Thanks to [h3ssto](https://twitter.com/h3ssto) for many hours of reviewing and typo fixing, as also my project supervisor [Stephan Kleber](https://www.uni-ulm.de/in/vs/inst/team/kleber/) for the feedback and brainstorming.
* Thanks to Rene Nyffenegger for publishing the base64-code.
