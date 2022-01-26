---
layout: post
title:  VMware x64 guest os EOP(CVE-2008-4279)
date: 2012-05-07 17:14:28
categories: vul
tags: CVE-2008-4279 VMware x64 EOP
---

# 漏洞描述: 
在VMware x64 Guest OS中, 利用其模拟指令的缺陷可导致以ring 0权限执行任意代码。

# 漏洞分析: 

下面的伪汇编片断提供了一个 x64体系下中断处理函数的典型实现，结合Vmware的指令模拟缺陷可产生安全漏洞：  

```

ISR_Entry_Point:

    ; For a long-mode (64-bit) ISR, RSP points to the following QWORDs:
    ;
    ;   [<error code>]
    ;   <return RIP> 
    ;   <return CS> 
    ;   <return RFLAGS>
    ;   [<return RSP> 
    ;   <return SS>]
    ;
    ; 一个典型的中断服务例程 首先会创建一个标准的陷阱帧。
    ; The first act of typical ISR prologue code is to build a standard
    ; "trap frame" on the stack -- saving registers, etc.

     ...                                        ; GS -> user or kernel

    ; If the CPL at the time of the fault (recorded in the two least
    ; significant bits of <return CS>) was zero, then the fault occurred
    ; in kernel mode; some OSes then assume that kernel GS is already
    ; active, and will therefore skip the SWAPGS instruction.

    ; 这里测试发生异常时的cpl，如果为0，则不会进行GS切换
    TEST    [return CS], (1, 2, or 3)           ; GS -> user or kernel
    JZ      Skip_Swap                           ; GS -> user or kernel

    ; If the previous mode was user mode, then it is assumed that the
    ; user GS base address is loaded, so SWAPGS will exchange the
    ; value in the KernelGSbase MSR (MSR C000_0102h) with the base
    ; address in the GS shadow descriptor, in effect switching from
    ; user GS to kernel GS.

    ; 如果发生中断时的cpl不等于0，即位于user-mode，则进行GS切换
    SWAPGS                                     ; before: GS -> user; after: GS -> kernel

  Skip_Swap:

    ; Now it's (supposedly) safe to use GS: to access GS-relative kernel
    ; data structures.

    ; 到这里时，操作系统认为GS已经切换到kernel-mode了
     ...                                       ; GS -> kernel

    ; At this point, the ISR switches back to user GS if returning to
    ; user mode; if returning to kernel mode, it leaves kernel GS loaded
    ; and therefore doesn't need to do SWAPGS.

    ; 这里进行测试cpl，如果之前模式为kernel模式，则跳过GS切换
    ; 否则 将GS切换为user-mode
    TEST    [return CS], (1, 2, or 3)          ; GS -> kernel
    JZ      Skip_Swap_Back                     ; GS -> kernel

    SWAPGS                                     ; before: GS -> kernel; after: GS -> user

  Skip_Swap_Back:

    IRETQ                                      ; GS -> user or kernel
```
由以上代码可知：

如果在异常处理函数的开始处第一个swapgs之前产生一个异常，那么跳入另一个异常处理函数后将不会进行GS切换，因为之前CPU模式为ring 0。如果进入第一个异常处理函数之前的CPU模式为user-mode,则会产生安全漏洞，因为此时CPU处于ring 0, 但gs还没有进行切换，位于user-mode。

同样在异常处理函数结尾，执行完swapgs之后发生异常，也会产生相同漏洞。
如果在用户模式下可以使内核在以上区域发生一个异常，将触发漏洞。
VMware模拟的指令可以在以上区域触发一个异常，可引发漏洞。


**Flaw #1**(CVE-2008-4279): 

x64体系定义规范(Canonical)地址的第48到63位必须是第47位的副本，否则为非规范地址，访问非规范（Non-Canonical）地址会触发#GP异常。

正常情况： jmp [xxx]，发生#GP时，TrapFrame的rip为发生异常时指令的地址。
但VMware 模拟的jmp [xxx] 间接跳转指令存在缺陷，发生#GP时，TrapFrame的rip为
jmp 的目标地址（即non-canonical地址)。

x64 Windows下的#GP异常，不会调用 iretq返回到user-mode的non-canonical地址,而是通过KiExceptionDispatch进行异常分发处理，返回到user-mode的ntdll的异常处理函数中。

尽管这样，当重复执行一个 jmp [non-canonical]时，最终将在non-canonical地址处产生一个硬件中断。这样在硬件中断处理函数处理完成执行iretq时，返回的rip为non-canonical地址，触发一个#GP异常， 由于此时已经将GS切换到user-mode，但CPU运行在ring 0，引发漏洞。


*注意*： 此漏洞不会发生在开启了“禁用加速”的情况下。

[参考](http://lists.grok.org.uk/pipermail/full-disclosure/2008-October/064860.html)