# Porting notes — SM-A736B / A736BXXSCGZF1

**Device:** Samsung Galaxy A73 5G  
**Firmware:** A736BXXSCGZF1 (Android 16 / One UI 8, August 2026 security patch)  
**Kernel:** `5.4.289-qgki-32200428-abA736BXXSCGZF1`  
**SoC:** SM7325 (Snapdragon 778G, arm64)

---

## What was built

Two CI artifacts are produced by `.github/workflows/build-a73x-A736BXXSCGZF1.yml`
on every push to `feat/a73x-A736BXXSCGZF1`:

| Artifact | File | Purpose |
|---|---|---|
| `a73x-A736BXXSCGZF1-payload` | `cve-2026-43499-app.so` | Exploit `.so` preloaded by Zygote to gain root via GhostLock (CVE-2026-43499) |
| `a73x-A736BXXSCGZF1-payload` | `cve-2026-43499` | Root-helper binary spawned by the exploit |
| `a73x-A736BXXSCGZF1-kernelsu-ko` | `android16-5.4_kernelsu-a73x-A736BXXSCGZF1-kdp.ko` | KernelSU v3.2.5 kernel module (Samsung KDP/RKP/DEFEX patch applied) |

Download from: **Actions → latest green run → Artifacts**  
`https://github.com/huanhoahongso3-collab/Root-My-Galaxy-Payloads/actions`

---

## Kernel 5.4 compat work (why it took many iterations)

KernelSU v3.2.5 targets upstream kernels ≥ 5.8.  Samsung QGKI 5.4 selectively
backports newer kernel internals while keeping `LINUX_VERSION_CODE = 5.4.x`,
so `#if LINUX_VERSION_CODE >= 5.9` guards are unreliable.  Every incompatibility
had to be discovered empirically from CI failures.

### Header shims (written to `$KOUT/include/linux/`)

| Header | Introduced upstream | Fix |
|---|---|---|
| `linux/pgtable.h` | 5.8 | Shim → `#include <asm/pgtable.h>` |
| `linux/minmax.h` | 5.14 | Shim → `#include <linux/kernel.h>` |

### Force-include compat header (`/tmp/ksu_compat.h` via `KCFLAGS=-include`)

Applied to every compiled object.  Guards everything under
`#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)`.

| Symbol / macro | Upstream version | Shim |
|---|---|---|
| `copy_to_kernel_nofault` | 5.8 | Inline wrapper → `probe_kernel_write` |
| `copy_from_kernel_nofault` | 5.8 | Inline wrapper → `probe_kernel_read` |
| `strncpy_from_user_nofault` | 5.8 | Inline wrapper → `strncpy_from_unsafe_user` |
| `copy_from_user_nofault` | 5.8 | Inline wrapper → `copy_from_user` |
| `copy_to_user_nofault` | 5.8 | Inline wrapper → `copy_to_user` |
| `__NR_faccessat2` (aarch64 #439) | 5.8 | `#define` |
| `security_inode_init_security_anon` | 5.9 | No-op macro |
| `TWA_RESUME` | 5.10 | `#define 1` |
| `SECCOMP_ARCH_NATIVE_NR` | 5.11 | `#define __NR_syscalls` |
| `struct selinux_policy` fwd-decl | 5.12 | Forward declaration |
| `linux/sched/task.h`, `pid.h`, `sched/signal.h` | — | Force-included (transitively required) |

### Source-level patches (Python inline script in CI step)

| File | Problem | Fix |
|---|---|---|
| `kernel/manager/pkg_observer.c` | Samsung QGKI 5.4 backported the 5.9 8-param `fsnotify handle_event` signature but kept the old field name; `ksu_handle_inode_event` still has the old 6-param signature | Generated an adapter wrapper under `#if LINUX_VERSION_CODE < 5.9`: 8-param wrapper → calls fn with 6 params |
| `kernel/policy/app_profile.c` | `atomic_set(&current->seccomp.filter_count, 0)` — `filter_count` added in 5.9 | Wrapped in `#if LINUX_VERSION_CODE >= 5.9` guard |
| `kernel/selinux/rules.c` | Whole file uses `selinux_state.policy` (RCU-protected policy ptr added in 5.12) | Wrapped in `#if >= 5.12`; 5.4 `#else` exports no-op `apply_kernelsu_rules()` and `handle_sepolicy()` |
| `kernel/selinux/sepolicy.c` | Uses `struct selinux_policy` and 5.9-era `filename_trans` internals that don't match Samsung QGKI 5.4 | Wrapped in `#if >= 5.12`; 5.4 `#else` exports stubs for all 20 `ksu_*` functions |
| `kernel/feature/selinux_hide.c` | `selinux_state.status_lock` / `status_page` added in 5.12 SELinux refactor | Wrapped in `#if >= 5.12`; 5.4 `#else` exports void stubs |

### Trade-offs of the stubs

The SELinux-related stubs mean **KernelSU's SELinux rule injection is a no-op on this
kernel**.  This is acceptable because:

1. The GhostLock exploit sets SELinux to permissive as part of the root chain.
2. For persistent root via KernelSU manager, SELinux permissive mode can be maintained
   through the manager app after first boot.
3. A proper 5.4-compatible SELinux rule injection would require rewriting the policy
   access path against `selinux_state.ss->policydb` — non-trivial and out of scope for
   a first working build.

---

## How to test on device

### Prerequisites

```
adb shell getprop ro.build.fingerprint
# Expected: samsung/a73xqxx/a73xq:16/.../A736BXXSCGZF1:user/release-keys

adb shell uname -r
# Expected: 5.4.289-qgki-32200428-abA736BXXSCGZF1
```

### Step 1 — Verify kernel module compatibility

```bash
# On your PC, check the .ko vermagic matches the device kernel string:
modinfo android16-5.4_kernelsu-a73x-A736BXXSCGZF1-kdp.ko | grep vermagic
# Should contain: 5.4.289-qgki-32200428-abA736BXXSCGZF1

# Check undefined symbols (should be 0 if kernel exports match):
llvm-nm -u android16-5.4_kernelsu-a73x-A736BXXSCGZF1-kdp.ko | wc -l
```

### Step 2 — Verify sched_blocked_reason event ID

```bash
adb shell cat /sys/kernel/tracing/events/sched/sched_blocked_reason/id
# target.h has SLIDE_TRACEFS_EVENT_ID = 73
# If different, update target.h and rebuild
```

### Step 3 — Push files to device

```bash
adb push cve-2026-43499-app.so /data/local/tmp/
adb push cve-2026-43499 /data/local/tmp/
adb push android16-5.4_kernelsu-a73x-A736BXXSCGZF1-kdp.ko /data/local/tmp/
adb shell chmod +x /data/local/tmp/cve-2026-43499
```

### Step 4 — Load the kernel module (requires exploit to run first)

The `.ko` must be loaded into the running kernel using KernelSU's late-load mechanism
**after** the exploit has granted root access.  You cannot `insmod` it before root.

```bash
# After exploit runs and you have root shell:
adb shell su -c "insmod /data/local/tmp/android16-5.4_kernelsu-a73x-A736BXXSCGZF1-kdp.ko"
adb shell su -c "dmesg | tail -20"   # look for KernelSU init messages
```

### Step 5 — Run the exploit

Follow the main repo README for the GhostLock exploit flow.  For this target the entry
point is the `.so` preload approach via Zygote injection.

### Step 6 — Verify root

```bash
adb shell su -c "id"
# Expected: uid=0(root) gid=0(root) ...

adb shell su -c "cat /proc/version"
# Should show the kernel string

adb shell su -c "getenforce"
# Will show Permissive (SELinux disabled by exploit; rules.c is a no-op stub)
```

---

## Known issues / TODO

| # | Issue | Severity | Notes |
|---|---|---|---|
| 1 | `SLIDE_TRACEFS_EVENT_ID = 73` unverified | High | Verify with `adb shell cat /sys/kernel/tracing/events/sched/sched_blocked_reason/id` |
| 2 | `SYSCTL_BOOTID_OFF = 0x0b2a9de1` odd alignment | Medium | Ends in an odd byte — unusual for a data symbol. Cross-check with `vmlinux.nm` or a crash log showing `boot_id` |
| 3 | `KIMAGE_TEXT_BASE = 0xffffffc008000000` unverified | Medium | Standard unslid base for QGKI 5.4. Confirm via `/proc/kallsyms _stext` on a reference device |
| 4 | SELinux rule injection is a no-op | Low | Device stays permissive after exploit.  A proper 5.4 SELinux port is a follow-up task |
| 5 | `copy_from/to_user_nofault` shim uses sleepable `copy_from_user` | Low | Loses "nofault" semantics; may panic if called in atomic/interrupt context.  In practice KernelSU uses these only in task context |
| 6 | No on-device test of the `.ko` | — | Module compiled but never loaded on real hardware yet |

---

## Build reproducibility

To rebuild locally or retrigger CI:

```bash
# Retrigger CI (requires secrets A73X_KERNEL_SOURCE_URL set in repo settings):
gh workflow run build-a73x-A736BXXSCGZF1.yml \
  --ref feat/a73x-A736BXXSCGZF1 \
  --repo huanhoahongso3-collab/Root-My-Galaxy-Payloads

# Or push any change to the feat branch:
git commit --allow-empty -m "retrigger CI" && git push
```

Kernel source for the build:
- **Base:** `A736BXXSCGZE2_kernel.tar.gz` (uploaded to GitHub Releases)
- **Patch:** `A736BXXSCGZF1` incremental patch (uploaded to GitHub Releases)
- Set `A73X_KERNEL_SOURCE_URL` and `A73X_KERNEL_PATCH_URL` secrets in repo Settings → Actions.
