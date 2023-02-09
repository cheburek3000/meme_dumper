# Meme dumper
---
## Summary
Why access memory through virtual address when you can access it through physical address, which is mapped without any protection? :)

With this idea in mind, this tool will run a server, which will dump you almost **any** memory, which would normally be protected from user/kernel.

## How to use
- Download and build [PS5SDK](https://github.com/PS5Dev/PS5SDK/) and set environment variable `PS5SDK` to folder with SDK.
- Run something on your PC to serve a logger, like `ncat -k -l 5655`
- Replace `PC_IP` and `PC_PORT` macros on lines 10-11 with your logger server's IP/port.
- This tool is firmware-dependent and will only work on firmwares supported by the SDK for kernel hacking. See PS5SDK README.md for this information.
- Set `PS5SDK_FW` to the correct target before building. For example, to target 4.03, `PS5SDK_FW` should be set to `0x403`.
- Run `./build.sh`.
- Deploy `bin/meme_dumper.elf` to ELF loader.
- Send your command to a target, for example `echo -n 'dump_paddr 0x21784000 0x1000' | nc $PS5_HOST 9081 > dump.bin`

## Commands
- `dump_vaddr 0x{vaddr} 0x{size}` - resolve virtual address to physical and ask kernel to dump `{size}` bytes from physical memory.
- `dump_paddr 0x{paddr} 0x{size}` - dump `{size}` bytes from physical memory from physical address.
- `dump_ranges` - dump all mapping from virtual memory to physical in human readable format.
- `stop` - stop the server, for example, to deploy another ELF.

## Not so useful commands
- `dump_abs 0x{absolute address} 0x{size}` - ask kernel to dump `{size}` bytes from specified address. Not very useful, since all page protections will apply to this query.
- `dump_base  0x{offset from kernel data base} 0x{size}` - ask kernel to dump `{size}` bytes from specified offset from kernel data base. Not very useful, since all page protections will apply to this query.

## Expected result
Log:
```
[+] kernel .data base is ffffffffdb050000, pipe 10->11, rw pair 12->121, pipe addr is ffffbbc23772d8c0
[+] kernel_pmap_store offset 0x3257a78, pm_pml4 0xffffbbbe21784000, pm_cr3 0x21784000, dmap_base 0xffffbbbe00000000
[+] got command = dump_paddr 0x21784000 0x1000
[+] dumping 0x1000 bytes from 0xffffbbbe21784000
[+] got command = stop
[+] stopping
stopped
```

## How it works
1. Find [kernel_pmap_store](https://github.com/freebsd/freebsd-src/blob/main/sys/amd64/amd64/pmap.c#L387) offset in kernel data. You can guess its location by specific signature (see `guess_kernel_pmap_store_offset` code).
2. Luckily it has **physical** and **virtual** addresses for PML4. And through them you can find physical memory mapped directly to the kernel memory (DMAP). See `PADDR_TO_DMAP` macro and [vmparam.h](https://github.com/freebsd/freebsd-src/blob/main/sys/amd64/include/vmparam.h#L167) from FreeBSD for reference.
3. Use page tables to convert any kernel address to physical address (see `vaddr_to_paddr` code).
4. Access data by physical address through DMAP.

## Authors
- cheburek3000

## Special thanks
- Specter (SDK and examples)
- Znullptr (SDK and examples)
- ChendoChap (SDK and examples)
