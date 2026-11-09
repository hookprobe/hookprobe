/*
 * cm5_relay_nano — Arduino Nano v3 (ATmega328P @ 16 MHz) firmware for the CM5 bench relays.
 *
 * Two relay channels, driven so that every failure leaves the board in the SAFE state
 * (powered, normal eMMC boot):
 *   D2 (PD2) -> relay 1 POWER   : wired through the NC contact in the CM5 5 V feed.
 *                                 de-energised = board powered. "power off" = energise.
 *   D3 (PD3) -> relay 2 RPIBOOT : NO contact across the nRPIBOOT jumper (to GND).
 *                                 de-energised = normal boot. "rpiboot" = energise.
 *   D13 (PB5) LED                : on while RPIBOOT is asserted.
 *
 * Safety:
 *   - At reset the pins are inputs (high-Z) and are then driven to "de-energised" first thing.
 *   - RPIBOOT auto-releases after 60 s; POWER-off auto-restores after 120 s — a crashed host
 *     never leaves the board unpowered or stuck in rpiboot.
 *
 * Serial 115200 8N1, one command per line (CR/LF), one reply line each:
 *   ?        -> "HQRELAY1 power=<1 powered|0 off> rpiboot=<0|1> up=<s>"
 *   P0 / P1  -> board power off / on               -> "OK power=<0|1>"
 *   B0 / B1  -> release / assert nRPIBOOT          -> "OK rpiboot=<0|1>"
 *   C<n>     -> power-cycle, n x 100 ms off (1..100) -> "OK cycled"
 *   anything else -> "ERR <reason>"
 * On boot it prints "HQRELAY1 ready".
 *
 * Most relay modules sold for Arduino are ACTIVE-LOW (IN pulled LOW = coil energised).
 * Build with -DACTIVE_LOW=0 for an active-high module.
 */
#include <avr/interrupt.h>
#include <avr/io.h>
#include <stdint.h>

#ifndef F_CPU
#define F_CPU 16000000UL
#endif
#ifndef ACTIVE_LOW
#define ACTIVE_LOW 1
#endif

#define PIN_POWER PD2
#define PIN_BOOT PD3
#define RPIBOOT_MAX_MS 60000UL
#define POWEROFF_MAX_MS 120000UL

static volatile uint32_t ms;
static uint8_t power_on = 1, rpiboot = 0;
static uint32_t boot_since, off_since;

ISR(TIMER1_COMPA_vect) { ms++; }

static uint32_t now(void) {
    uint32_t t;
    cli();
    t = ms;
    sei();
    return t;
}

static void drive(uint8_t pin, uint8_t energise) {
    uint8_t high = ACTIVE_LOW ? !energise : energise;
    if (high)
        PORTD |= (1 << pin);
    else
        PORTD &= ~(1 << pin);
}

static void set_power(uint8_t on) {
    power_on = on;
    drive(PIN_POWER, !on); /* energise = NC opens = unpowered */
    off_since = now();
}

static void set_boot(uint8_t on) {
    rpiboot = on;
    drive(PIN_BOOT, on);
    if (on)
        PORTB |= (1 << PB5);
    else
        PORTB &= ~(1 << PB5);
    boot_since = now();
}

static void wait_ms(uint32_t d) {
    uint32_t t0 = now();
    while (now() - t0 < d) {
    }
}

static void uart_init(void) {
    UCSR0A = (1 << U2X0);
    UBRR0 = 16; /* 115200 @ 16 MHz with U2X (-0.8 %) */
    UCSR0B = (1 << RXEN0) | (1 << TXEN0);
    UCSR0C = (1 << UCSZ01) | (1 << UCSZ00);
}

static void put(char c) {
    while (!(UCSR0A & (1 << UDRE0))) {
    }
    UDR0 = c;
}

static void puts_(const char *s) {
    while (*s)
        put(*s++);
}

static void putu(uint32_t v) {
    char b[11];
    int i = 0;
    do {
        b[i++] = '0' + v % 10;
        v /= 10;
    } while (v);
    while (i)
        put(b[--i]);
}

static void line_end(void) { puts_("\r\n"); }

static void handle(const char *c, uint8_t n) {
    if (n == 1 && c[0] == '?') {
        puts_("HQRELAY1 power=");
        put(power_on ? '1' : '0');
        puts_(" rpiboot=");
        put(rpiboot ? '1' : '0');
        puts_(" up=");
        putu(now() / 1000);
    } else if (n == 2 && c[0] == 'P' && (c[1] == '0' || c[1] == '1')) {
        set_power(c[1] == '1');
        puts_("OK power=");
        put(power_on ? '1' : '0');
    } else if (n == 2 && c[0] == 'B' && (c[1] == '0' || c[1] == '1')) {
        set_boot(c[1] == '1');
        puts_("OK rpiboot=");
        put(rpiboot ? '1' : '0');
    } else if (n >= 2 && n <= 4 && c[0] == 'C') {
        uint16_t k = 0;
        for (uint8_t i = 1; i < n; i++) {
            if (c[i] < '0' || c[i] > '9') {
                puts_("ERR bad number");
                line_end();
                return;
            }
            k = k * 10 + (c[i] - '0');
        }
        if (k < 1 || k > 100) {
            puts_("ERR range 1..100");
        } else {
            set_power(0);
            wait_ms((uint32_t)k * 100);
            set_power(1);
            puts_("OK cycled");
        }
    } else {
        puts_("ERR unknown");
    }
    line_end();
}

int main(void) {
    /* Safe state before anything else: both coils de-energised. */
    DDRD |= (1 << PIN_POWER) | (1 << PIN_BOOT);
    DDRB |= (1 << PB5);
    drive(PIN_POWER, 0);
    drive(PIN_BOOT, 0);

    /* 1 kHz tick: Timer1 CTC, /64 prescaler, OCR1A = 249. */
    TCCR1A = 0;
    TCCR1B = (1 << WGM12) | (1 << CS11) | (1 << CS10);
    OCR1A = 249;
    TIMSK1 = (1 << OCIE1A);
    sei();

    uart_init();
    set_power(1);
    set_boot(0);
    puts_("HQRELAY1 ready");
    line_end();

    char buf[16];
    uint8_t n = 0;
    for (;;) {
        uint32_t t = now();
        if (rpiboot && t - boot_since > RPIBOOT_MAX_MS)
            set_boot(0);
        if (!power_on && t - off_since > POWEROFF_MAX_MS)
            set_power(1);
        if (UCSR0A & (1 << RXC0)) {
            char ch = UDR0;
            if (ch == '\r' || ch == '\n') {
                if (n)
                    handle(buf, n);
                n = 0;
            } else if (n < sizeof buf) {
                buf[n++] = ch;
            } else {
                n = 0; /* overlong line: drop it */
            }
        }
    }
}
