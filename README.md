# TraceON
A x32Dbg Plugin that single steps through the instructions and stops the trace at once when the Instruction pointer is outside any known DLL memory region. Can be used to detect Self injected PE/ dump out shellcode from memory. Works slower than expected.

Build the plugin, copy the built TraceOn.dp32 file in x32Dbg's plugin folder. Run x32Dbg and start debugging an exe, stop at any instruction and start the Trace->Trace Into feature. If during tracing EIP is found at any memory address that doesn't fall inside loaded DLL regions, tracing will stop and log the EIP. At this point you can dump out the memory region containing EIP to further investigate.
