#!/usr/bin/env python3
"""
Parchea GTDT.aml para el Galaxy S5 Mini (MSM8228 / Cortex-A7):
  - Corrige los 4 IRQs del ARM Generic Timer a los valores correctos
  - Recalcula el checksum ACPI

Uso: python3 patch_gtdt.py <ruta/a/GTDT.aml>
"""

import sys
import struct

# IRQs correctos para Cortex-A7 (GIC PPI números 13, 14, 11, 10)
# En numeración GIC: PPI_n = 16 + n
CORRECT_IRQS = {
    "Secure EL1 (PPI 13)":      (0x30, 0x1D),
    "Non-Secure EL1 (PPI 14)":  (0x38, 0x1E),
    "Virtual Timer (PPI 11)":   (0x40, 0x1B),
    "Non-Secure EL2 (PPI 10)":  (0x48, 0x1A),
}

def acpi_checksum(data: bytearray) -> int:
    """El checksum ACPI se calcula de forma que la suma de todos los bytes == 0 (mod 256)."""
    return (-sum(data)) & 0xFF

def patch_gtdt(path: str):
    with open(path, "rb") as f:
        data = bytearray(f.read())

    # Validar firma
    if data[0:4] != b"GTDT":
        print(f"ERROR: '{path}' no tiene firma GTDT (found: {data[0:4]})")
        sys.exit(1)

    print(f"Archivo: {path}  ({len(data)} bytes)")
    print(f"Checksum original: 0x{data[9]:02X}  (sum total = 0x{sum(data) & 0xFF:02X})\n")

    # Parchear IRQs
    for name, (offset, new_irq) in CORRECT_IRQS.items():
        old_irq = struct.unpack_from("<I", data, offset)[0]
        struct.pack_into("<I", data, offset, new_irq)
        status = "✓ ya correcto" if old_irq == new_irq else f"0x{old_irq:02X} → 0x{new_irq:02X}"
        print(f"  {name:30s} offset 0x{offset:02X}:  {status}")

    # Poner checksum en 0 antes de calcular
    data[9] = 0
    data[9] = acpi_checksum(data)
    print(f"\nChecksum nuevo: 0x{data[9]:02X}  (sum total = 0x{sum(data) & 0xFF:02X})")

    with open(path, "wb") as f:
        f.write(data)
    print(f"\nGTDT.aml actualizado correctamente.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Uso: python3 {sys.argv[0]} <GTDT.aml>")
        sys.exit(1)
    patch_gtdt(sys.argv[1])
