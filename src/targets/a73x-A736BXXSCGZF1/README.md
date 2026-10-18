# SM-A736B / A736BXXSCGZF1

**Device:** Samsung Galaxy A73 5G  
**Kernel:** 5.4.289-qgki-32200428-abA736BXXSCGZF1  
**Android:** 16 (One UI 8) / API 36  
**SoC:** SM7325 (Snapdragon 778G)

## Status

Payload compiles. On-device testing incomplete.

## Known blockers

### 1. Missing KernelSU `.ko` (required)

The `.so` payload alone is not sufficient. A KernelSU kernel module compiled against the **exact** kernel headers for `5.4.289-qgki-32200428-abA736BXXSCGZF1` is required. Without this `.ko`, the exploit has no mechanism to install KernelSU into the running kernel.

To build it:
1. Obtain the matching kernel source / headers from Samsung Open Source (https://opensource.samsung.com) for build `A736BXXSCGZF1`
2. Build KernelSU as a loadable module (`CONFIG_MODULES=y` must be set — verify in the shipped kernel config)
3. Place the resulting `.ko` in `artifacts/a73x-A736BXXSCGZF1/`

### 2. `SLIDE_TRACEFS_EVENT_ID` unverified

Value `73` was inferred from symbol analysis. Verify on device:
```
adb shell cat /sys/kernel/tracing/events/sched/sched_blocked_reason/id
```

### 3. `SYSCTL_BOOTID_OFF` odd alignment

`0x0b2a9de1` ends in an odd byte — unusual for a data symbol. Cross-check against `vmlinux.nm` output for the `boot_id` sysctl entry.

### 4. `KIMAGE_TEXT_BASE` history

Went through three "critical fix" reversions. Final value `0xffffffc008000000` is the standard unslid base for 5.4 QGKI. Confirm against `/proc/kallsyms _stext` if you have a rooted reference device or a crash log.
