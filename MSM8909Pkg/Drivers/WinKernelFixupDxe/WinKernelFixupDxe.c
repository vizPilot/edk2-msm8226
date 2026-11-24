/** @file
  Windows RT kernel fix-up at ExitBootServices.

  The CP14 debug unit is fused off on the MSM8226/MSM8909 family: every
  extended debug register access (DBGOSLSR, DBGPRSR, DBGDSCRext, DBGVCR,
  DBGBCR/BVR/WCR/WVR) traps as UNDEFINED.

  The ARM kernel programs those registers unconditionally on every
  processor. Its own guard reads ID_DFR0 and bugchecks UNSUPPORTED_PROCESSOR
  (0x5D) when ID_DFR0 [3:0] < 4, but these parts report the ARMv7.1 debug
  architecture, so the guard passes and the very first CP14 access in
  KiInitializeDebugRegisters raises an undefined instruction instead. That
  is why an early stop shows up as DRIVER_VERIFIER_DETECTION_VIOLATION
  0xC4/0x91 (the "0x5D disguised as 0xC4") instead of a clean 0x5D.

  At ExitBootServices winload has loaded and relocated ntoskrnl.exe but not
  started it. This driver scans loader memory for the per-processor debug
  register initialisation call sites and replaces the call with NOPs. The
  kernel then keeps its per-processor breakpoint/watchpoint counts at zero
  and never touches the debug registers again. Hardware breakpoints are
  unavailable, which nothing in WinPE needs.

  Supported kernels:
    6.2.8520.0  (fbl_eeap, patterns from the Samsung Goya port)
    6.3.9600.17328 (Windows RT 8.1 RTM free, checked on a real image)

  Note: 8.1 has no 8520-style "PatchGuard CP14 flag" site. On 8520 that site
  was KD bookkeeping which took the value from a global byte; on 8.1 the same
  bookkeeping reads DBGDSCRext itself, but only after a gate:
      ldrb.w r3,[Prcb+0x338] ; tst.w r3,#0x10 ; beq <skip>
  (INITKDBG 0x88c5e4/0x88d3c8, INIT twins, 8 occurrences in the image). Two
  optional entries below force that gate off, so the DBGDSCRext access at
  0x88c60e/0x88d61c/... can never run even if the flag is set. They are marked
  optional because on a boot without a kernel debugger the bit is already
  clear and the required two sites are all that matter.

  A small square in the bottom-right corner of the screen reports the result
  (it stays visible behind the Windows logo and the stop screen):
    green  = every site of at least one supported kernel was patched
    yellow = only some sites found (kernel build not in the tables)
    red    = nothing found (other kernel build or not Windows)
    cyan   = patched, and a pending asynchronous abort was taken here
    blue   = patched, a pending asynchronous abort could not be taken here

  Asynchronous (imprecise) aborts: a RELEASE firmware runs with them masked
  (ArmPkg CpuDxe only unmasks them in DEBUG builds), so a bus error caused by
  firmware code stays pending and is delivered the moment the OS unmasks
  aborts - early in the kernel, before the HAL timer is set up, as
  KMODE_EXCEPTION_NOT_HANDLED. At ExitBootServices this driver reads ISR.A
  and, if an abort is pending, unmasks aborts for a moment with its own Data
  Abort handler installed so the abort is consumed here.

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <Library/BaseMemoryLib.h>
#include <Library/CacheMaintenanceLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PcdLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/Cpu.h>
#include <Protocol/DebugSupport.h>

UINT32 GoyaReadIsr (VOID);
UINT32 GoyaReadCpsr (VOID);
UINT32 GoyaReadDfsr (VOID);
VOID   GoyaTakeAsyncAbort (VOID);

STATIC EFI_CPU_ARCH_PROTOCOL  *mCpu;
STATIC volatile UINT32        mAbortTaken;
STATIC volatile UINT32        mAbortDfsr;

/**
  Data Abort handler used only around GoyaTakeAsyncAbort: note the abort and return to its caller
  with asynchronous aborts masked again (CPSR.A), Thumb state from lr.
**/
STATIC
VOID
EFIAPI
AsyncAbortHandler (
  IN EFI_EXCEPTION_TYPE  ExceptionType,
  IN EFI_SYSTEM_CONTEXT  SystemContext
  )
{
  EFI_SYSTEM_CONTEXT_ARM  *Ctx = SystemContext.SystemContextArm;

  mAbortTaken++;
  mAbortDfsr = GoyaReadDfsr ();
  Ctx->CPSR  = (Ctx->CPSR & ~(UINT32)(0x20 | 0x0600FC00)) | 0x100 | ((Ctx->LR & 1) ? 0x20 : 0);
  Ctx->PC    = Ctx->LR & ~(UINT32)1;
}

/**
  Returns 0 = no abort pending, 1 = a pending abort was taken here, 2 = pending, could not take it.
**/
STATIC
UINTN
FlushAsyncAbort (
  VOID
  )
{
  UINTN  Result;

  if ((GoyaReadIsr () & BIT8) == 0) {
    return 0;
  }
  if ((mCpu == NULL) || EFI_ERROR (mCpu->RegisterInterruptHandler (mCpu, EXCEPT_ARM_DATA_ABORT, AsyncAbortHandler))) {
    return 2;
  }
  mAbortTaken = 0;
  GoyaTakeAsyncAbort ();
  mCpu->RegisterInterruptHandler (mCpu, EXCEPT_ARM_DATA_ABORT, NULL);
  Result = ((mAbortTaken != 0) && ((GoyaReadIsr () & BIT8) == 0)) ? 1 : 2;
  DEBUG ((DEBUG_WARN, "WinKernelFixup: pending asynchronous abort %a (DFSR 0x%x)\n", (Result == 1) ? "taken" : "NOT cleared", mAbortDfsr));
  return Result;
}

#define GROUP_8520  0
#define GROUP_9600  1
#define GROUP_COUNT 2

typedef struct {
  CONST CHAR8    *Name;
  UINT8          Group;
  UINT8          Pattern[32];     // 6.3.9600 site 0 is 30 bytes
  UINTN          Length;
  UINTN          PatchOffset;     // offset of the bytes to replace
  UINT8          Patch[4];
  UINTN          PatchLength;
  BOOLEAN        Optional;      // patched when found, but not required for "green"
} KERNEL_SITE;

STATIC CONST KERNEL_SITE  mSites[] = {
  //
  // ---------------- Windows 8 build 8520 (PXA986 / Goya) ----------------
  //
  //  mrc p15,0,r3,c0,c1,2 (ID_DFR0); ands r3,#0xf; cmp r3,#4; blo.w <bugcheck 0x5D>;
  //  bl <KiInitializeDebugRegisters>; pop {r2,r3,fp,pc}
  {
    "8520: KiInitializeProcessor debug init",
    GROUP_8520,
    { 0x10, 0xee, 0x51, 0x3f, 0x13, 0xf0, 0x0f, 0x03, 0x04, 0x2b, 0xd3, 0xf0,
      0xf9, 0xad, 0x00, 0xf0, 0xd1, 0xf9, 0xbd, 0xe8, 0x0c, 0x88 },
    22, 14, { 0x00, 0xbf, 0x00, 0xbf }, 4                   // nop; nop
  },
  //  ldr r3,=<flag>; ldrb r3,[r3]; cbz r3,...; bl <KiInitializeDebugRegisters>
  {
    "8520: resume path debug init",
    GROUP_8520,
    { 0x0f, 0x4b, 0x1b, 0x78, 0x9b, 0xb1, 0xff, 0xf7, 0x70, 0xfd },
    10, 6, { 0x00, 0xbf, 0x00, 0xbf }, 4                    // nop; nop
  },
  //  PatchGuard context setup (INIT): ldr r3,=<CP14 debug present flag>; ldrb r2,[r3];
  //  ... ands r2,r3,#0x20.  Force the flag clear with movs r2,#0.
  {
    "8520: PatchGuard CP14 debug flag",
    GROUP_8520,
    { 0x1a, 0x78, 0x98, 0xf8, 0xe8, 0x32, 0x83, 0xea, 0x42, 0x13, 0x13, 0xf0, 0x20, 0x02 },
    14, 0, { 0x00, 0x22 }, 2                                // movs r2,#0
  },
  //
  // ------------- Windows RT 8.1 build 6.3.9600.17328 (free) -------------
  //
  // 0x4de84c: called once per processor (from 0x63de32), same shape as the 8520 site.
  //   mrc p15,0,r3,c0,c1,2 ; and r3,#0xf ; cmp r3,#4 ; blo.w <0x527388 = bugcheck 0x5D>
  //   bl 0x4de86c (KiInitializeDebugRegisters) ; pop {r2,r3,fp,pc}
  // The two branch immediates are PC-relative, so the bytes do not change when the
  // image is relocated. PatchOffset 22 = the 'bl'.
  {
    "9600: KiInitializeProcessor debug init",
    GROUP_9600,
    { 0x2d, 0xe9, 0x0c, 0x48, 0x0d, 0xf1, 0x08, 0x0b,
      0x10, 0xee, 0x51, 0x3f, 0x03, 0xf0, 0x0f, 0x03,
      0x04, 0x2b, 0xc8, 0xf0, 0x93, 0xa5, 0x00, 0xf0,
      0x03, 0xf8, 0xbd, 0xe8, 0x0c, 0x88 },
    30, 22, { 0x00, 0xbf, 0x00, 0xbf }, 4                   // nop; nop
  },
  // 0x53c7f0: restore-thread path (0x53c740), gated by the byte at 0x63a04a
  //   ldr r3,=<flag> ; ldrb r3,[r3] ; cbz r3,.. ; bl 0x4de86c
  // Only these two sites call KiInitializeDebugRegisters in 6.3.9600.17328.
  {
    "9600: resume path debug init",
    GROUP_9600,
    { 0x0c, 0x4b, 0x1b, 0x78, 0x9b, 0xb1, 0xa2, 0xf7, 0x39, 0xf8 },
    10, 6, { 0x00, 0xbf, 0x00, 0xbf }, 4                    // nop; nop
  },
  //
  // The sites below are hardening, not required. 8.1 has no 8520-style
  // "PatchGuard CP14 flag": the equivalent KD bookkeeping lives in INITKDBG /
  // INIT and is guarded by 'ldrb.w r3,[Prcb+0x338] ; tst.w r3,#0x10'. When the
  // gate is set the code reads/writes DBGDSCRext (p14) immediately. Forcing r3
  // to 0 turns every 'tst #0x10' into "not active", so the branch is always
  // taken and the CP14 access never happens. On a boot with no kernel debugger
  // the bit is already clear and these patches change nothing.
  //
  //  ldrb.w r3,[r8,#0x338] ; tst.w r3,#0x10   (5 occurrences)
  {
    "9600: INITKDBG debug-active gate (r8)",
    GROUP_9600,
    { 0x98, 0xf8, 0x38, 0x33, 0x13, 0xf0, 0x10, 0x0f },
    8, 0, { 0x00, 0x23, 0x00, 0xbf }, 4,                    // movs r3,#0 ; nop
    TRUE
  },
  //  ldrb.w r3,[r9,#0x338] ; tst.w r3,#0x10   (3 occurrences)
  {
    "9600: INITKDBG debug-active gate (r9)",
    GROUP_9600,
    { 0x99, 0xf8, 0x38, 0x33, 0x13, 0xf0, 0x10, 0x0f },
    8, 0, { 0x00, 0x23, 0x00, 0xbf }, 4,                    // movs r3,#0 ; nop
    TRUE
  },
};

#define SITE_COUNT  (sizeof (mSites) / sizeof (mSites[0]))

// Number of sites per kernel group: a group is "complete" only when all of its
// sites were found.
STATIC CONST UINTN  mGroupSites[GROUP_COUNT] = { 3, 2 };

STATIC EFI_EVENT              mExitBootServicesEvent;
STATIC EFI_MEMORY_DESCRIPTOR  *mMap;
STATIC UINTN                  mMapBufferSize;

STATIC
VOID
DrawMarker (
  IN UINT32  Color
  )
{
  UINT32  *Fb     = (UINT32 *)(UINTN)FixedPcdGet32 (PcdMipiFrameBufferAddress);
  UINT32  Stride  = FixedPcdGet32 (PcdMipiFrameBufferWidth);
  UINT32  Width   = FixedPcdGet32 (PcdMipiFrameBufferWidth);
  UINT32  Height  = FixedPcdGet32 (PcdMipiFrameBufferHeight);
  UINT32  X, Y;

  if ((Fb == NULL) || (Width < 24) || (Height < 24)) {
    return;
  }

  // SimpleFbDxe presents 32 bpp, XRGB (masks 0x00FF0000/0x0000FF00/0x000000FF),
  // PixelsPerScanLine == width.
  for (Y = Height - 20; Y < Height - 4; Y++) {
    for (X = Width - 20; X < Width - 4; X++) {
      Fb[Y * Stride + X] = Color;
    }
  }

  WriteBackDataCacheRange (Fb + (Height - 20) * Stride, 16 * Stride * 4);
}

/**
  Scan one region (2-byte aligned, Thumb code) for every site.
**/
STATIC
VOID
ScanRegion (
  IN     UINT8  *Base,
  IN     UINTN  Size,
  IN OUT UINTN  *Found
  )
{
  UINT16  *P;
  UINT16  *End;
  UINTN   S;
  UINT16  First[SITE_COUNT];

  if (Size < 64) {
    return;
  }

  for (S = 0; S < SITE_COUNT; S++) {
    First[S] = (UINT16)(mSites[S].Pattern[0] | (mSites[S].Pattern[1] << 8));
  }

  End = (UINT16 *)(Base + Size - 32);
  for (P = (UINT16 *)Base; P < End; P++) {
    for (S = 0; S < SITE_COUNT; S++) {
      if ((*P == First[S]) && (CompareMem (P, mSites[S].Pattern, mSites[S].Length) == 0)) {
        UINT8  *Bl = (UINT8 *)P + mSites[S].PatchOffset;

        CopyMem (Bl, mSites[S].Patch, mSites[S].PatchLength);
        WriteBackInvalidateDataCacheRange (Bl, mSites[S].PatchLength);
        InvalidateInstructionCacheRange (Bl, mSites[S].PatchLength);
        Found[S]++;
        DEBUG ((DEBUG_INFO, "WinKernelFixup: patched %a at %p\n", mSites[S].Name, Bl));
      }
    }
  }
}

STATIC
VOID
EFIAPI
OnExitBootServices (
  IN EFI_EVENT  Event,
  IN VOID       *Context
  )
{
  UINTN                  MapSize = mMapBufferSize;
  UINTN                  MapKey;
  UINTN                  DescSize;
  UINT32                 DescVer;
  UINT8                  *D;
  UINTN                  Found[SITE_COUNT];
  UINTN                  GroupFound[GROUP_COUNT];
  UINTN                  S, G;
  UINTN                  TotalFound = 0;
  BOOLEAN                Complete   = FALSE;
  UINTN                  Abort;

  ZeroMem (Found, sizeof (Found));
  ZeroMem (GroupFound, sizeof (GroupFound));

  if ((mMap == NULL) || EFI_ERROR (gBS->GetMemoryMap (&MapSize, mMap, &MapKey, &DescSize, &DescVer))) {
    DrawMarker (0x00FF00FF);    // magenta: could not read the memory map
    return;
  }

  for (D = (UINT8 *)mMap; D < (UINT8 *)mMap + MapSize; D += DescSize) {
    EFI_MEMORY_DESCRIPTOR  *Desc = (EFI_MEMORY_DESCRIPTOR *)D;

    // winload loads the kernel into loader memory; boot services data is scanned too in case
    // a loader allocates its image buffers there
    if (((Desc->Type == EfiLoaderCode) || (Desc->Type == EfiLoaderData) || (Desc->Type == EfiBootServicesData)) &&
        (Desc->NumberOfPages > 0))
    {
      ScanRegion ((UINT8 *)(UINTN)Desc->PhysicalStart, EFI_PAGES_TO_SIZE ((UINTN)Desc->NumberOfPages), Found);
    }
  }

  for (S = 0; S < SITE_COUNT; S++) {
    if (Found[S] != 0) {
      TotalFound++;
      if (!mSites[S].Optional) {
        GroupFound[mSites[S].Group]++;
      }
      DEBUG ((DEBUG_INFO, "WinKernelFixup: site %a: %d hit(s)\n", mSites[S].Name, Found[S]));
    }
  }

  for (G = 0; G < GROUP_COUNT; G++) {
    if ((mGroupSites[G] != 0) && (GroupFound[G] == mGroupSites[G])) {
      Complete = TRUE;
    }
    DEBUG ((DEBUG_INFO, "WinKernelFixup: group %d: %d/%d sites\n", G, GroupFound[G], mGroupSites[G]));
  }

  Abort = FlushAsyncAbort ();
  if (!Complete) {
    DrawMarker ((TotalFound != 0) ? 0x00FFFF00 : 0x00FF0000);
  } else {
    DrawMarker ((Abort == 0) ? 0x0000FF00 : (Abort == 1) ? 0x0000FFFF : 0x000000FF);
  }
}

EFI_STATUS
EFIAPI
WinKernelFixupDxeEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  UINTN   MapSize = 0;
  UINTN   MapKey;
  UINTN   DescSize;
  UINT32  DescVer;

  // The map grows while the OS loader runs; leave plenty of room (no allocation is allowed at EBS)
  gBS->GetMemoryMap (&MapSize, NULL, &MapKey, &DescSize, &DescVer);
  mMapBufferSize = MapSize + 256 * DescSize;
  mMap           = AllocateRuntimePool (mMapBufferSize);
  gBS->LocateProtocol (&gEfiCpuArchProtocolGuid, NULL, (VOID **)&mCpu);

  return gBS->CreateEvent (
                EVT_SIGNAL_EXIT_BOOT_SERVICES,
                TPL_NOTIFY,
                OnExitBootServices,
                NULL,
                &mExitBootServicesEvent
                );
}
