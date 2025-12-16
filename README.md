# RAD Studio LLDB plugin

This is a RAD Studio LLDB plugin for following a branch/call instruction
when using LLDB.

To load the plugin into LLDB, use the following command:  
```
command script import "<full location of arch_utils.py>"
```   
eg, 
```
command script import "C:\\Program Files (x86)\\Embarcadero\\Studio\\37.0\\bin\\windows\\lldb\\arch_utils.py"
```   

After loading, 2 new commands are immediately available.  
These commands are:

* is_branch_or_call \<addr\> [debug]
* follow \<addr\> [debug]

Usage examples:
* ```is_branch_or_call 0xd7300f```
* ```follow 0xd7300f```

is_branch_or_call will return a boolean and an address, or a boolean followed by None.
follow will follow the branch/call instruction at the given address, and disassemble the instruction at the target address that is pointed to by the given address.

Dec 2025,  
CheeWee, Chua  
 