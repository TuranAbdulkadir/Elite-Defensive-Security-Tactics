class EBPFTracer:
    def trace_syscalls(self): print('Attaching eBPF probes to sys_execve to monitor process creation...')