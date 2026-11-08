# Arduino Nano v3 (ATmega328P @ 16 MHz) — CM5 bench relay firmware. Needs gcc-avr avr-libc avrdude.
#   make                      build cm5_relay_nano.hex
#   make flash PORT=/dev/serial/by-id/usb-1a86_...   flash (tries the new 115200, then the old 57600 bootloader)
#   make ACTIVE_LOW=0 ...     for an active-high relay module
ACTIVE_LOW ?= 1
PORT ?=
CFLAGS = -mmcu=atmega328p -DF_CPU=16000000UL -DACTIVE_LOW=$(ACTIVE_LOW) -Os -Wall -Wextra -std=gnu11

all: cm5_relay_nano.hex

cm5_relay_nano.elf: cm5_relay_nano.c
	avr-gcc $(CFLAGS) -o $@ $<
	avr-size $@

cm5_relay_nano.hex: cm5_relay_nano.elf
	avr-objcopy -O ihex -R .eeprom $< $@

flash: cm5_relay_nano.hex
	@test -n "$(PORT)" || { echo "set PORT=/dev/serial/by-id/..."; exit 2; }
	@case "$$(readlink -f $(PORT))" in /dev/ttyUSB0|/dev/ttyUSB1|/dev/ttyUSB2) echo "refusing $(PORT): CM5 console / LTE modem"; exit 2;; esac
	avrdude -p m328p -c arduino -P $(PORT) -b 115200 -U flash:w:cm5_relay_nano.hex:i || \
	avrdude -p m328p -c arduino -P $(PORT) -b 57600 -U flash:w:cm5_relay_nano.hex:i

.PHONY: all flash
