While reverse engineering LockBit 4.0 Green, I encountered a frustrating decompilation issue that IDA Pro users rarely face but can't easily fix. 
This post explains the root cause and provides an automated solution.
**We can read :**

"""Upon disassembling the main malware subroutine in IDA, we immediately encounter a decompilation issue evidenced by numerous `STACK[offset]` variables. These are supposed to represent local variables within the subroutine, but IDA fails to properly identify and name them."""

![](./posts/image_lockbit/lockbit-stack-01.png)

The question is: how can we fix this in IDA to obtain clean pseudocode?
![](./posts/image_lockbit/lockbit-stack-02.png)
This problem is due to when IDA need to reconstruct the stack frame of every function. For this he calculate the SP delta - the values that show how the pointer (ESP/RSP)  evolve during the execution. 

Interestingly, Binary Ninja handles the stack frame differently the stack frame differently cause i don't have this decompilation problem.
![](./posts/image_lockbit/lockbit-stack-03.png)
## Understanding the Root Cause

IDA reconstructs each function's stack frame by tracking the Stack Pointer (ESP/RSP) delta throughout execution. The SP delta represents how the stack pointer changes relative to the function's entry point.

**The formula IDA uses:**
``Stack_Offset = ESP_Offset - SP_Delta``

When this calculation is incorrect, IDA cannot properly identify local variables, resulting in generic STACK[offset] references instead of meaningful variable names.

**Why Binary Ninja handles it better:**
Binary Ninja uses a different stack analysis algorithm that's more robust to obfuscation techniques commonly found in ransomware.
### Easy solution :
If you want a no brain solution to fix one error you can just apply this and it should solve the error :

Stack / Ida View ``Alt + K`` open "Difference between old and new SP". In the pseudo-C we have the value 0xC74 If we put this it solve the problem
![](./posts/image_lockbit/lockbit-stack-02.png)

![](./posts/image_lockbit/lockbit-stack-04.png)
Which now matches with the binja decompilation.
![](./posts/image_lockbit/lockbit-stack-05.png)
This works, but with 4000+ lines and multiple errors, we need to have a better solution.

The script is available [here](https://github.com/Duntss/Ida_script/blob/main/correct_stack.py) if you want to see it now.

Understanding the mechanism: for each instruction that access to the stack via \[esp+offset], IDA do :
```
Stack_Offset = ESP_Offset - SP_Delta
```
Concrete example :
- Instruction : `lea esi, [esp+9ACh]`
- ESP_Offset = ``0x9AC``
- SP_Delta actual = 4
- Result : 0x9AC - 4 = 2472
We want :
- Target : ``STACK[0xC74]``
- New SP_Delta : 0x9AC-0xC74 = 728
- Result : 0x9AC-728 = 3188 -> `STACK[0xC74]`

The solution is to enforce alignment between the assembly and the decompiled pseudo-code.

The script works in 4 steps :
#### 1. Extract the offset from the stack :
#### 2. Scan ESP Instruction
#### 3. Calcul the aligments
#### 4. Apply the corrections
Finally we apply new SP deltas via the IDA API :
```python
for a in alignments:
    try:
        idc.add_user_stkpnt(a['ea'], a['new_sp'])
        print(f"[+] 0x{a['ea']:X}: SP {a['current_sp']} -> {a['new_sp']}")
    except Exception as e:
        print(f"[!] Error: {e}")

# Recompile the pseudo-code
idaapi.decompile(func_ea)
```

### Usage :
#### Automatic mode
```python
# Analyse the current function
fix_current_function()

# Apply the corrections
fix_current_function(False)
```
#### Debug mode
```python
# Analyse the instruction on the cursor
show_instruction_info

# Or an adress
show_instruction_info(0x4160A7)
```
#### Manual Correction
If you know wich STACK offset you want :
```python
# Force [esp + 9ACh] point to STACK[0xC74]
manual_fix_instruction(0x416A7, 0xC74)
```

### Why this approach 
I initially tried locating errors using heuristics but it was the wrong way. Here we enforce consistency. Also we use the STACK offset from Hex-Rays wich is generally correct. It handle every format (symbolic name, hex, decimal, negativ value).
#### Limitations 
Can be slow on functions with many errors.
## Conclusion

Stack frame reconstruction errors are rare in modern disassemblers, but 
sophisticated malware like LockBit 4.0 can still cause issues. This 
automated approach ensures consistency between assembly and pseudocode 
by leveraging Hex-Rays' own STACK offset calculations.

**Key takeaways:**
- Manual SP delta fixes work but don't scale
- Automated enforcement of assembly-to-pseudocode alignment is more reliable
- Different disassemblers handle obfuscation differently (consider using multiple tools)

The complete script is available on [GitHub](your-link).

## References
- [ChuongDong's LockBit 4.0 Analysis](https://www.chuongdong.com/reverse%20engineering/2025/03/15/Lockbit4Ransomware/#overview)
- [IDA Pro Stack Frame Documentation](...)
- [Hex-Rays Decompiler API](...)
[ChuongDong LockBit Ransomware v4.0]
