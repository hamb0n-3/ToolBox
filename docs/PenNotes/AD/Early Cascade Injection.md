 [Guido Miggelenbrink](https://www.outflank.nl/blog/2024/10/15/introducing-early-cascade-injection-from-windows-process-creation-to-stealthy-injection/)

- Combines [Early Bird APC Injection](https://0xmani.medium.com/early-bird-injection-05027fbfb794) technique with the [EDR-Preloading](https://www.malwaretech.com/2024/02/bypassing-edrs-with-edr-preload.html) technique by Marcus Hutchins

	> APC (Asynchronous Procedure Calls) Injection-> Initialization / Uses existing process
	> Early Bird APC Injection -> Early as possible in Initialization / Create process (in suspended state)
	> EDR-Preloading -> Before EDR DLL's are started (but last of most DLLs)
	> Early Cascade -> avoids queuing cross-process APCs / minimal remote process injection.

### Process Creation APIs

- APIs that create a process invoke the NAPI `NtCreateUserProcess` in `ntdll.dll`.
	- responsible for switching control from the API to the kernel -> where `NtCreateUserProcess` is executed
- `dwCreationFlags` parameter 
	- controls process creation

![[Pasted image 20241017103458.png]]

### Kernel-mode and user-mode process creation

- `NtCreateUserProcess` -> **kernel-mode** -> **user-mode**
- **kernel-mode**
	- Opens image file of app -> maps to memory -> creates specific process & thread objects -> maps  `ntdll.dll` into process - > creates initial thread
		- `CREATE_SUSPENDED` flag = optional
	- `ntdll.dll`
		- first and only DLL loaded
		- contains `LdrInitializeThunk`
	- `LdrInitializeThunk`
		- handles user-mode part of process creation before app's main entry point runs
		- "image loader"
		- Prefixed with `Ldr` in `ntdll.dll`
	- (Resuming after suspension) `LdrInitializeThunk` -> **user-mode** -> fully initialized -> executes app's main entry point
### User-mode process creation: `LdrInitializeThunk`
- `LdrInitializeThunk`
	- first function executed in **user-mode**
	- "Usually" initial point for malware and EDRs
	- *Windows Internals, Part 1* -> list of tasks
	- *x64dbg* and *IDA Pro* -> subordinate functions (the sauce)