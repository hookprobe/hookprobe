# U-Boot script for the NanoPi M5 heqk bench netboot. Compile with the mkimage from
# tools/build/m5-firmware-build.sh:
#   mkimage -A arm64 -T script -C none -n heqk-m5 -d boot.cmd ~/heqk-m5-bench/tftp/heqk-m5/boot.scr.uimg
# The firmware's baked-in boot command (m5-netboot/bootcommand.txt) DHCPs, fetches this script
# and sources it on every boot; without a TFTP server it falls back to `bootflow scan -lb`.
#
# Hand-off: booti enters the image at EL2 with x0 = FDT (U-Boot does not switch to EL1 on this
# board). By default the FDT is U-Boot's own control DT (mainline rk3576-nanopi-m5.dts). booti
# copies it and fixes up /memory from the DDR blob's ATAGs and /chosen, so heqk takes RAM from it
# (data pack §4). A heqk-m5.dtb in the TFTP directory overrides it.
echo "== heqk-m5 netboot from ${serverip}"
# Not every U-Boot environment defines fdt_addr_r (the M5's does: 0x52000000; qemu_arm64's does not,
# and an unset one silently loads the DTB at the default load address on top of scriptaddr).
if test -z "${fdt_addr_r}"; then setenv fdt_addr_r 0x48000000; fi
tftpboot ${kernel_addr_r} heqk-m5/heqk-m5.img || exit
if tftpboot ${fdt_addr_r} heqk-m5/heqk-m5.dtb; then
  setenv heqk_fdt ${fdt_addr_r}
else
  setenv heqk_fdt ${fdtcontroladdr}
fi
if test -z "${heqk_fdt}"; then echo "== no FDT address: refusing booti"; exit; fi
echo "== booti ${kernel_addr_r} (fdt ${heqk_fdt})"
booti ${kernel_addr_r} - ${heqk_fdt}
