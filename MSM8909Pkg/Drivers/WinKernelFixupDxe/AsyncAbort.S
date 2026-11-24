// Helpers for WinKernelFixupDxe: look for an asynchronous (imprecise) abort that the firmware left
// pending, and take it while the firmware's handler is still installed.
// SPDX-License-Identifier: BSD-2-Clause-Patent
  .syntax unified
  .arm
  .text
  .align 2

// UINT32 GoyaReadIsr (VOID): ISR (c12): bit 8 A = asynchronous abort pending, bit 7 I, bit 6 F
  .global GoyaReadIsr
  .type GoyaReadIsr, %function
GoyaReadIsr:
  mrc   p15, 0, r0, c12, c1, 0
  bx    lr

// UINT32 GoyaReadCpsr (VOID)
  .global GoyaReadCpsr
  .type GoyaReadCpsr, %function
GoyaReadCpsr:
  mrs   r0, cpsr
  bx    lr

// UINT32 GoyaReadDfsr (VOID)
  .global GoyaReadDfsr
  .type GoyaReadDfsr, %function
GoyaReadDfsr:
  mrc   p15, 0, r0, c5, c0, 0
  bx    lr

// VOID GoyaTakeAsyncAbort (VOID): unmask asynchronous aborts for a moment. A pending abort is taken
// here; the driver's Data Abort handler returns to lr with aborts masked again.
  .global GoyaTakeAsyncAbort
  .type GoyaTakeAsyncAbort, %function
GoyaTakeAsyncAbort:
  cpsie a
  isb
  nop
  nop
  nop
  nop
  nop
  nop
  nop
  nop
  cpsid a
  isb
  bx    lr
