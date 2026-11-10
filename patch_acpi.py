#!/usr/bin/env python3
"""
Parchea FACP.aml y MADT.aml para el Galaxy S5 Mini (MSM8228 / Cortex-A7)

FACP:
  - Deshabilita PSCI (ARM_BOOT_ARCH = 0x0000) → Windows usa Parking Protocol
    en vez de intentar HVC/PSCI que no existe en MSM8228

MADT:
  - Expande las estructuras GICC de 40 → 76 bytes (formato ACPI 5.0 completo)
  - Agrega los MPIDR correctos para cada core
  - Agrega direcciones GICv2 virtuales (GICV/GICH)
  - Recalcula el checksum

Uso:
  python3 patch_acpi.py <directorio/AcpiTables>
  Ejemplo: python3 patch_acpi.py MSM8909Pkg/AcpiTables
"""

import sys
import struct
import os

# ─── MSM8226/8228 GIC addresses ───────────────────────────────────────────────
GICC_BASE  = 0xF9002000   # GIC CPU Interface (común a todos los cores)
GICV_BASE  = 0xF9006000   # GIC Virtual CPU Interface
GICH_BASE  = 0xF9004000   # GIC Hypervisor Interface
VGIC_MAINT_IRQ = 25       # PPI 9 → GIC IRQ 25

# MPIDR de cada core Cortex-A7 en MSM8228 (quad-core, cluster 0)
MPIDR = [0x80000000, 0x80000001, 0x80000002, 0x80000003]

def acpi_checksum(data: bytearray) -> int:
    return (-sum(data)) & 0xFF

def fix_checksum(data: bytearray) -> bytearray:
    data[9] = 0
    data[9] = acpi_checksum(data)
    return data

# ─── FACP patch ───────────────────────────────────────────────────────────────
def patch_facp(path: str):
    with open(path, "rb") as f:
        data = bytearray(f.read())

    if data[0:4] != b"FACP":
        print(f"  ERROR: no es FACP ({data[0:4]})")
        return

    # ARM_BOOT_ARCH está en offset 0x74 (2 bytes), FADT revision >= 5
    old_val = struct.unpack_from("<H", data, 0x74)[0]
    # 0x0000 = no PSCI; Windows usará Parking Protocol del MADT
    struct.pack_into("<H", data, 0x74, 0x0000)
    fix_checksum(data)

    with open(path, "wb") as f:
        f.write(data)
    print(f"  FACP: ARM_BOOT_ARCH  0x{old_val:04X} → 0x0000  (PSCI deshabilitado)")
    print(f"  FACP: checksum nuevo = 0x{data[9]:02X}")

# ─── MADT patch ───────────────────────────────────────────────────────────────
# Formato GICC ACPI 5.0 completo = 76 bytes (0x4C)
# Ref: ACPI 5.0 spec, tabla 5-50
GICC_SIZE_OLD = 0x28   # 40 bytes  (formato pre-5.0)
GICC_SIZE_NEW = 0x4C   # 76 bytes  (ACPI 5.0+)

def build_gicc(cpu_num, uid, flags, park_ver, perf_irq, parked_addr,
               gicc_base, gicv_base, gich_base, vgic_irq,
               gicr_base, mpidr):
    """Construye una estructura GICC de 76 bytes según ACPI 5.0 (tabla 5-50).
    Offsets: 0x00 type, 0x01 len, 0x02 res2, 0x04 cpu_if_num, 0x08 uid,
             0x0C flags, 0x10 park_ver, 0x14 perf_irq, 0x18 parked(8),
             0x20 gicc(8), 0x28 gicv(8), 0x30 gich(8), 0x38 vgic_irq(4),
             0x3C gicr(8), 0x44 mpidr(8)  → total 0x4C = 76 bytes
    """
    s  = struct.pack("<B", 0x0B)          # Type = GICC (0x0B)
    s += struct.pack("<B", GICC_SIZE_NEW) # Length = 76
    s += struct.pack("<H", 0x0000)        # Reserved
    s += struct.pack("<I", cpu_num)       # CPU Interface Number
    s += struct.pack("<I", uid)           # ACPI Processor UID
    s += struct.pack("<I", flags)         # Flags
    s += struct.pack("<I", park_ver)      # Parking Protocol Version
    s += struct.pack("<I", perf_irq)      # Performance Interrupt GSIV
    s += struct.pack("<Q", parked_addr)   # Parked Address
    s += struct.pack("<Q", gicc_base)     # GICC Base Address
    s += struct.pack("<Q", gicv_base)     # GICV Base Address
    s += struct.pack("<Q", gich_base)     # GICH Base Address
    s += struct.pack("<I", vgic_irq)      # VGIC Maintenance Interrupt
    s += struct.pack("<Q", gicr_base)     # GICR Slice Base Address
    s += struct.pack("<Q", mpidr)         # MPIDR
    # Verificar tamaño
    assert len(s) == GICC_SIZE_NEW, f"GICC size mismatch: {len(s)}, esperado {GICC_SIZE_NEW}"
    return s

def patch_madt(path: str):
    with open(path, "rb") as f:
        data = bytearray(f.read())

    if data[0:4] != b"APIC":
        print(f"  ERROR: no es MADT/APIC ({data[0:4]})")
        return

    # Parsear el MADT: header = 44 bytes (8+6+8+4+4+4+4+4+4)
    # Header ACPI estándar = 36 bytes, luego 4 bytes Local Controller Address y 4 bytes flags
    MADT_HEADER_SIZE = 44
    local_ctrl_addr = struct.unpack_from("<I", data, 36)[0]
    madt_flags      = struct.unpack_from("<I", data, 40)[0]

    # Recolectar todas las subtablas (tipo, datos)
    offset = MADT_HEADER_SIZE
    subtables = []
    while offset < len(data):
        stype  = data[offset]
        slen   = data[offset + 1]
        sdata  = bytes(data[offset:offset + slen])
        subtables.append((stype, sdata))
        offset += slen

    # Reconstruir MADT reemplazando las GICCs (tipo 0x0B)
    new_subtables = bytearray()
    gicc_count = 0
    for stype, sdata in subtables:
        if stype == 0x0B:  # GICC
            # Extraer campos existentes del formato viejo (40 bytes)
            cpu_num     = struct.unpack_from("<I", sdata, 4)[0]
            uid         = struct.unpack_from("<I", sdata, 8)[0]
            flags       = struct.unpack_from("<I", sdata, 12)[0]
            park_ver    = struct.unpack_from("<I", sdata, 16)[0]
            perf_irq    = struct.unpack_from("<I", sdata, 20)[0]
            parked_addr = struct.unpack_from("<Q", sdata, 24)[0]
            # gicc_base en el formato viejo = sdata[32:40], usualmente 0
            old_base    = struct.unpack_from("<Q", sdata, 32)[0]

            new_gicc = build_gicc(
                cpu_num     = cpu_num,
                uid         = uid,
                flags       = flags,
                park_ver    = park_ver,
                perf_irq    = perf_irq,
                parked_addr = parked_addr,
                gicc_base   = GICC_BASE,
                gicv_base   = GICV_BASE,
                gich_base   = GICH_BASE,
                vgic_irq    = VGIC_MAINT_IRQ,
                gicr_base   = 0x0,
                mpidr       = MPIDR[gicc_count],
            )
            new_subtables += new_gicc
            print(f"  MADT GICC[{gicc_count}]: 40 → 76 bytes  "
                  f"(MPIDR=0x{MPIDR[gicc_count]:08X}  parked=0x{parked_addr:08X})")
            gicc_count += 1
        else:
            new_subtables += sdata

    # Reconstruir MADT completo
    new_madt = bytearray()
    new_madt += data[:36]                        # header ACPI estándar (firma + length + revision + checksum + oemid + ...)
    new_madt += struct.pack("<I", local_ctrl_addr)
    new_madt += struct.pack("<I", madt_flags)
    new_madt += new_subtables

    # Actualizar el campo Table Length en el header
    struct.pack_into("<I", new_madt, 4, len(new_madt))
    fix_checksum(new_madt)

    with open(path, "wb") as f:
        f.write(new_madt)
    print(f"  MADT: largo  {len(data)} → {len(new_madt)} bytes")
    print(f"  MADT: checksum nuevo = 0x{new_madt[9]:02X}")

# ─── Main ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Uso: python3 {sys.argv[0]} <directorio/AcpiTables>")
        sys.exit(1)

    base = sys.argv[1]
    facp = os.path.join(base, "FACP.aml")
    madt = os.path.join(base, "MADT.aml")

    for path in [facp, madt]:
        if not os.path.exists(path):
            print(f"ERROR: no encontré {path}")
            sys.exit(1)

    print("── Parcheando FACP ──────────────────────────────")
    patch_facp(facp)
    print()
    print("── Parcheando MADT ──────────────────────────────")
    patch_madt(madt)
    print()
    print("Listo. Reconstruí el firmware y flasheá.")
