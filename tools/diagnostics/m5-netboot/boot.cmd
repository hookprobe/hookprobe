# U-Boot script for the NanoPi M5 heqk bench netboot. Compile with the mkimage from
# tools/build/m5-firmware-build.sh:
#   mkimage -A arm64 -T script -C none -n heqk-m5 -d boot.cmd ~/heqk-m5-bench/tftp/heqk-m5/boot.scr.uimg
# U-Boot (SPI-NOR) runs it after DHCP (dnsmasq dhcp-boot), or by hand:
#   setenv autoload no; dhcp; tftpboot ${scriptaddr} heqk-m5/boot.scr.uimg; source ${scriptaddr}
#
# Hand-off: booti enters the image at EL2 with x0 = FDT (U-Boot does not switch to EL1 on this
# board). The FDT is U-Boot's own control DT (mainline rk3576-nanopi-m5.dts) with /memory fixed up
# from the DDR blob's ATAGs, so heqk takes RAM from it (data pack §4). A heqk-m5.dtb in the TFTP
# directory overrides it.
echo "== heqk-m5 netboot from ${serverip}"
tftpboot ${kernel_addr_r} heqk-m5/heqk-m5.img || exit
if tftpboot ${fdt_addr_r} heqk-m5/heqk-m5.dtb; then
  setenv heqk_fdt ${fdt_addr_r}
else
  fdt addr ${fdtcontroladdr}
  fdt move ${fdtcontroladdr} ${fdt_addr_r} 0x40000
  setenv heqk_fdt ${fdt_addr_r}
fi
echo "== booti ${kernel_addr_r} (fdt ${heqk_fdt})"
booti ${kernel_addr_r} - ${heqk_fdt}
