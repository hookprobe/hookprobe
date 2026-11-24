// SPDX-License-Identifier: AGPL-3.0-only
//! The DWC2 device driver against the register-level model: identity check, core reset, enumeration (chapter-9
//! requests, descriptors, BOS + MS OS 2.0), bulk transfers, and the whole HQFL exchange over USB — the real
//! driver, the real server, the real verifier.
mod common;
use common::mock_dwc2::*;
use common::*;
use flashstub::desc;
use flashstub::dwc2::{self, Dwc2, Event, InitErr};
use flashstub::image::IMG_MAX;
use flashstub::proto::{s, t, MAX_CHUNK};
use flashstub::server::{Server, State};
use std::cell::RefCell;
use std::rc::Rc;

const BUILD: [u8; 32] = [0xAB; 32];

fn core(dedicated: bool) -> (Rc<RefCell<Model>>, MockRegs) {
    let m = Rc::new(RefCell::new(Model::new(DWC2_ID, dedicated)));
    (m.clone(), MockRegs(m))
}

fn out_buf() -> Vec<u8> {
    vec![0u8; 66048]
}

#[test]
fn a_core_that_is_not_dwc2_is_refused_before_any_write() {
    for id in [0x5533_310A, 0, 0xFFFF_FFFF] {
        let m = Rc::new(RefCell::new(Model::new(id, true)));
        let mut ob = out_buf();
        match Dwc2::init(MockRegs(m.clone()), &mut ob, &BUILD) {
            Err((InitErr::NotDwc2(got), hw)) => assert_eq!((got, hw.snpsid), (id, id)),
            Ok(_) => panic!("accepted GSNPSID {id:#x}"),
            Err(e) => panic!("{e:?}"),
        }
        assert_eq!(m.borrow().writes, 0, "no register written on a refused core");
    }
}

#[test]
fn identify_reads_the_hardware_configuration() {
    let (_, mut r) = core(true);
    let hw = Dwc2::<MockRegs>::identify(&mut r);
    assert!(Dwc2::<MockRegs>::is_dwc2(hw.snpsid));
    assert_eq!((hw.fifo_words, hw.dev_eps, hw.dedicated_fifos, hw.hs_phy()), (0x0FF0, 5, true, 1));
}

#[test]
fn too_small_fifo_or_too_few_endpoints_is_refused() {
    let m = Rc::new(RefCell::new(Model::new(DWC2_ID, true)));
    m.borrow_mut().hwcfg[2] = 100 << 16;
    let mut ob = out_buf();
    assert!(matches!(Dwc2::init(MockRegs(m), &mut ob, &BUILD), Err((InitErr::FifoTooSmall(100), _))));
    let m = Rc::new(RefCell::new(Model::new(DWC2_ID, true)));
    m.borrow_mut().hwcfg[1] &= !(0xF << 10);
    m.borrow_mut().hwcfg[1] |= 1 << 10;
    assert!(matches!(Dwc2::init(MockRegs(m), &mut ob, &BUILD), Err((InitErr::TooFewEndpoints(1), _))));
}

/// Enumerate like a host: reset, descriptors at address 0, SET_ADDRESS, descriptors, SET_CONFIGURATION.
fn enumerate(host: &mut Host, pump: &mut dyn FnMut()) {
    host.reset(pump);
    let d = host.control_in(pump, setup_pkt(0x80, 6, 0x0100, 0, 64)).unwrap();
    assert_eq!(d, desc::DEVICE);
    host.set_address(pump, 7);
    assert_eq!(host.m.borrow().address(), 7);
    let d = host.control_in(pump, setup_pkt(0x80, 6, 0x0100, 0, 18)).unwrap();
    assert_eq!(u16::from_le_bytes([d[8], d[9]]), desc::VID);
    let c9 = host.control_in(pump, setup_pkt(0x80, 6, 0x0200, 0, 9)).unwrap();
    assert_eq!(c9.len(), 9);
    let total = u16::from_le_bytes([c9[2], c9[3]]);
    let c = host.control_in(pump, setup_pkt(0x80, 6, 0x0200, 0, total)).unwrap();
    assert_eq!(c, desc::config(2, 512));
    host.control_nodata(pump, setup_pkt(0x00, 9, 1, 0, 0)).unwrap();
}

#[test]
fn enumeration_descriptors_and_standard_requests() {
    for (dedicated, done_style) in [(true, false), (false, false), (true, true)] {
        let (m, r) = core(dedicated);
        m.borrow_mut().csrst_done_style = done_style;
        let mut ob = out_buf();
        let mut usb = Dwc2::init(r, &mut ob, &BUILD).expect("init");
        assert_eq!(m.borrow().soft_resets, 1);
        assert!(m.borrow().connected(), "soft-connected after init");
        let gusb = m.borrow_mut().read(dwc2::GUSBCFG);
        assert_eq!(gusb & (dwc2::GUSBCFG_FDMOD | dwc2::GUSBCFG_FHMOD), dwc2::GUSBCFG_FDMOD, "device mode forced");
        assert_eq!(gusb & 0x7, 0x7, "the firmware's PHY / calibration bits are kept");
        assert_eq!((gusb >> 10) & 0xF, 9, "8-bit UTMI+ turnaround");
        let mut events = vec![];
        let mut host = Host { m: m.clone(), addr: 0 };
        let mut pump = || {
            if let Some(e) = usb.poll() {
                events.push(e);
            }
        };
        enumerate(&mut host, &mut pump);
        // strings
        let s0 = host.control_in(&mut pump, setup_pkt(0x80, 6, 0x0300, 0, 255)).unwrap();
        assert_eq!(s0, [4, 3, 0x09, 0x04]);
        let s3 = host.control_in(&mut pump, setup_pkt(0x80, 6, 0x0303, 0x0409, 255)).unwrap();
        let serial: String = s3[2..].chunks(2).map(|c| c[0] as char).collect();
        assert_eq!(serial, "HQFL-ABABABABABABABAB");
        let s2 = host.control_in(&mut pump, setup_pkt(0x80, 6, 0x0302, 0x0409, 255)).unwrap();
        assert_eq!(s2.len(), 2 + 2 * desc::PRODUCT.len());
        assert!(host.control_in(&mut pump, setup_pkt(0x80, 6, 0x0309, 0x0409, 255)).is_err(), "no string 9: STALL");
        // device qualifier, other-speed configuration, BOS, MS OS 2.0 set (a 162-byte, 3-packet data stage)
        assert_eq!(host.control_in(&mut pump, setup_pkt(0x80, 6, 0x0600, 0, 10)).unwrap(), desc::QUALIFIER);
        assert_eq!(host.control_in(&mut pump, setup_pkt(0x80, 6, 0x0700, 0, 255)).unwrap(), desc::config(7, 64));
        let bos = host.control_in(&mut pump, setup_pkt(0x80, 6, 0x0F00, 0, 255)).unwrap();
        assert_eq!(bos, desc::BOS);
        let vendor_code = bos[bos.len() - 2];
        let set = host.control_in(&mut pump, setup_pkt(0xC0, vendor_code, 0, 7, 512)).unwrap();
        assert_eq!(set, desc::MSOS20_SET);
        assert_eq!(&set[14..20], b"WINUSB");
        // a wLength that cuts the answer on a packet boundary: exactly 64 bytes, no extra packet
        let part = host.control_in(&mut pump, setup_pkt(0xC0, vendor_code, 0, 7, 64)).unwrap();
        assert_eq!(part, desc::MSOS20_SET[..64]);
        // config / status / interface
        assert_eq!(host.control_in(&mut pump, setup_pkt(0x80, 8, 0, 0, 1)).unwrap(), [1]);
        assert_eq!(host.control_in(&mut pump, setup_pkt(0x80, 0, 0, 0, 2)).unwrap(), [1, 0]);
        assert_eq!(host.control_in(&mut pump, setup_pkt(0x82, 0, 0, 0x82, 2)).unwrap(), [0, 0]);
        assert_eq!(host.control_in(&mut pump, setup_pkt(0x81, 10, 0, 0, 1)).unwrap(), [0]);
        host.control_nodata(&mut pump, setup_pkt(0x01, 11, 0, 0, 0)).unwrap();
        // unsupported requests STALL, and the next SETUP works
        assert!(host.control_in(&mut pump, setup_pkt(0xC0, 0x99, 0, 0, 8)).is_err());
        assert!(host.control_nodata(&mut pump, setup_pkt(0x00, 9, 5, 0, 0)).is_err(), "configuration 5 does not exist");
        assert!(host.control_nodata(&mut pump, setup_pkt(0x40, 1, 0, 0, 0)).is_err(), "vendor OUT");
        assert_eq!(host.control_in(&mut pump, setup_pkt(0x80, 6, 0x0100, 0, 18)).unwrap(), desc::DEVICE);
        // SET_FEATURE(ENDPOINT_HALT) on the IN endpoint, then CLEAR_FEATURE (WebUSB clearHalt)
        host.control_nodata(&mut pump, setup_pkt(0x02, 3, 0, 0x82, 0)).unwrap();
        assert_eq!(host.control_in(&mut pump, setup_pkt(0x82, 0, 0, 0x82, 2)).unwrap(), [1, 0]);
        assert_eq!(m.borrow_mut().in_token(7, 2), Tok::Stall);
        host.control_nodata(&mut pump, setup_pkt(0x02, 1, 0, 0x82, 0)).unwrap();
        assert_eq!(m.borrow_mut().in_token(7, 2), Tok::Nak, "halt cleared; nothing to send");
        drop(pump);
        assert!(events.contains(&Event::Reset));
        assert!(events.contains(&Event::Enumerated { high_speed: true }));
        assert!(events.contains(&Event::Configured));
        assert!(usb.configured() && usb.high_speed());
        assert!(usb.stats.stalls >= 4);
    }
}

#[test]
fn bulk_echo_frames_of_every_shape() {
    let (m, r) = core(true);
    let mut ob = out_buf();
    let mut usb = Dwc2::init(r, &mut ob, &BUILD).unwrap();
    let mut host = Host { m: m.clone(), addr: 0 };
    let usb_cell = RefCell::new(&mut usb);
    let mut pump = || {
        let mut u = usb_cell.borrow_mut();
        u.poll();
    };
    enumerate(&mut host, &mut pump);
    for len in [16usize, 24, 511, 513, 1000, 1025, 65_568, 66_047] {
        let data: Vec<u8> = (0..len).map(|i| (i * 7 + len) as u8).collect();
        host.bulk_out(&mut pump, 1, &data).unwrap();
        for _ in 0..8 {
            pump();
        }
        let got = usb_cell.borrow().frame().map(|f| f.to_vec());
        assert_eq!(got.as_deref(), Some(&data[..]), "frame of {len} bytes");
        // the endpoint NAKs until re-armed
        assert_eq!(m.borrow_mut().out_token(7, 1, &[0; 8]), Tok::Nak);
        let resp: Vec<u8> = data.iter().take(len.min(100)).map(|b| b ^ 0x5A).collect();
        {
            let mut u = usb_cell.borrow_mut();
            u.rearm_out();
            if resp.len() % 512 != 0 {
                assert!(u.send(&resp));
            }
        }
        if resp.len() % 512 != 0 {
            assert_eq!(host.bulk_in(&mut pump, 2).unwrap(), resp);
        }
    }
    assert_eq!(usb_cell.borrow().stats.out_frames, 8);
    assert!(!usb_cell.borrow_mut().send(&[0u8; 512][..]), "a 512-multiple response is never sent");
}

/// The stub's main loop over USB, with the HQFL client driving it.
struct UsbLink<'a> {
    host: Host,
    usb: Dwc2<'a, MockRegs>,
    srv: Server<'a>,
    m: RamMedium,
}

impl Link for UsbLink<'_> {
    fn call(&mut self, frame: &[u8]) -> Vec<u8> {
        let UsbLink { host, usb, srv, m } = self;
        let mut pump = || {
            flashstub::service(usb, srv, m);
        };
        host.bulk_out(&mut pump, desc::EP_OUT as usize, frame).expect("bulk OUT");
        host.bulk_in(&mut pump, desc::EP_IN as usize).expect("bulk IN")
    }
}

#[test]
fn end_to_end_over_usb_enumerate_verify_write_readback() {
    for dedicated in [true, false] {
        let (slot, disk) = good_disk();
        let (m, r) = core(dedicated);
        let mut ob = out_buf();
        let usb = Dwc2::init(r, &mut ob, &BUILD).unwrap();
        let (mut img, h) = (vec![0u8; IMG_MAX], hboot_ref());
        let srv = Server::new(config(1, false), &h, &mut img);
        let mut link = UsbLink { host: Host { m: m.clone(), addr: 0 }, usb, srv, m: RamMedium::with_old(disk.bytes.len() as u64 / 512 + 64) };
        {
            let UsbLink { host, usb, srv, m } = &mut link;
            let mut pump = || {
                flashstub::service(usb, srv, m);
            };
            enumerate(host, &mut pump);
        }
        let mut c = Client::new(link);
        c.faults.short_on = vec![3];
        c.faults.crc_flip_on = vec![5];
        let info = c.hello();
        assert_eq!((info.ty, info_max_chunk(&info) as usize), (t::INFO, MAX_CHUNK));
        assert_eq!(c.verify(&slot, MAX_CHUNK).unwrap().0, 5);
        let (dg, resumes) = c.write(&disk.bytes, MAX_CHUNK, 4).unwrap();
        assert_eq!(resumes, 2);
        let r = c.finish(&dg);
        assert_eq!((r.status, &r.payload[..32], r.payload[32]), (s::OK, &dg[..], 3));
        let l = &c.link;
        assert_eq!(&l.m.data[..disk.bytes.len()], &disk.bytes[..]);
        assert_eq!(l.m.order.last(), Some(&0), "MBR last");
        assert!(l.usb.stats.out_frames > 80 && l.usb.stats.out_overflow == 0);
        assert!(l.usb.stats.in_frames + 1 >= l.usb.stats.out_frames, "every response went out (the last completion is seen on the next poll)");
        println!("  over USB (dedicated FIFOs: {dedicated}): {} frames in, {} out, {} FIFO pushes, {} sector writes",
            l.usb.stats.out_frames, l.usb.stats.in_frames, m.borrow().fifo_pushes, l.m.writes);
    }
}

#[test]
fn a_bus_reset_mid_write_ends_the_session_and_the_board_has_no_mbr() {
    let (slot, disk) = good_disk();
    let (m, r) = core(true);
    let mut ob = out_buf();
    let usb = Dwc2::init(r, &mut ob, &BUILD).unwrap();
    let (mut img, h) = (vec![0u8; IMG_MAX], hboot_ref());
    let srv = Server::new(config(1, false), &h, &mut img);
    let mut link = UsbLink { host: Host { m: m.clone(), addr: 0 }, usb, srv, m: RamMedium::with_old(20000) };
    {
        let UsbLink { host, usb, srv, m } = &mut link;
        enumerate(host, &mut || {
            flashstub::service(usb, srv, m);
        });
    }
    let mut c = Client::new(link);
    c.hello();
    c.verify(&slot, MAX_CHUNK).unwrap();
    assert_eq!(c.call(t::WBEGIN, &(disk.bytes.len() as u64).to_le_bytes()).status, s::OK);
    let d = &disk.bytes[..MAX_CHUNK];
    let mut p = 0u64.to_le_bytes().to_vec();
    p.extend_from_slice(&flashstub::proto::crc32(d).to_le_bytes());
    p.extend_from_slice(&[0; 4]);
    p.extend_from_slice(d);
    assert_eq!(c.call(t::WRITE, &p).status, s::OK);
    assert!(c.link.m.admitted);
    // cable pulled and re-plugged: the host resets the bus
    let UsbLink { host, usb, srv, m: med } = &mut c.link;
    host.reset(&mut || {
        flashstub::service(usb, srv, med);
    });
    assert_eq!(srv.state(), State::Init);
    assert!(med.lba0_is_zero() && !med.admitted);
    assert!(!usb.configured(), "the host must enumerate again");
}
