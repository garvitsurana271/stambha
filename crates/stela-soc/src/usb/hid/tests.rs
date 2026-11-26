use super::*;
use crate::{
    dwc3::xhci::tests::host,
    usb::{
        Speed,
        hub::{Hub, Ports},
    },
};

fn control(p: &mut Peripheral, setup: [u8; 8], out: &[u8]) -> Result<Vec<u8>, ()> {
    assert_eq!(
        p.packet(0, Token::Setup, &mut setup.clone()),
        Ok(Reply::Ack(8))
    );
    let length = usize::from(u16::from_le_bytes([setup[6], setup[7]]));
    let mut reply = Vec::new();
    if setup[0] & 0x80 != 0 {
        while reply.len() < length {
            let mut packet = [0; EP0_PACKET];
            match p.packet(0, Token::In, &mut packet).unwrap() {
                Reply::Ack(n) => {
                    reply.extend_from_slice(&packet[..n]);
                    if n < EP0_PACKET {
                        break;
                    }
                }
                Reply::Stall => return Err(()),
                Reply::Nak => panic!("control NAK"),
            }
        }
        match p.packet(0, Token::Out, &mut []).unwrap() {
            Reply::Ack(0) => Ok(reply),
            _ => Err(()),
        }
    } else {
        for chunk in out.chunks(EP0_PACKET) {
            if p.packet(0, Token::Out, &mut chunk.to_vec()).unwrap() == Reply::Stall {
                return Err(());
            }
        }
        match p.packet(0, Token::In, &mut []).unwrap() {
            Reply::Ack(0) => Ok(reply),
            _ => Err(()),
        }
    }
}

fn setup(kind: u8, request: u8, value: u16, index: u16, length: u16) -> [u8; 8] {
    let [v0, v1] = value.to_le_bytes();
    let [i0, i1] = index.to_le_bytes();
    let [l0, l1] = length.to_le_bytes();
    [kind, request, v0, v1, i0, i1, l0, l1]
}

fn enumerate(p: &mut Peripheral) {
    p.reset().unwrap();
    let device = control(p, setup(0x80, GET_DESCRIPTOR, 0x100, 0, 64), &[]).unwrap();
    assert_eq!(device, DEVICE_DESCRIPTOR);
    control(p, setup(0, SET_ADDRESS, 3, 0, 0), &[]).unwrap();
    assert_eq!(p.address, 3);
    control(p, setup(0, SET_CONFIGURATION, 1, 0, 0), &[]).unwrap();
    control(p, setup(0x21, SET_IDLE, 0, 0, 0), &[]).unwrap();
}

#[test]
fn peripheral_refuses_touch() {
    let mut p = Peripheral::new();
    enumerate(&mut p);
    let frame = stela_drivers::input::multitouch::Frame::lifted(0);
    assert!(p.input(Input::Touch(frame)).is_err());
    // Nothing queued on any interface.
    for endpoint in [KEYBOARD_ENDPOINT, POINTER_ENDPOINT, MOUSE_ENDPOINT] {
        assert_eq!(p.ready_at(endpoint), None);
    }
}

#[test]
fn descriptors_describe_a_composite_keyboard_and_pointer() {
    let mut p = Peripheral::new();
    let config = control(&mut p, setup(0x80, GET_DESCRIPTOR, 0x200, 0, 9), &[]).unwrap();
    assert_eq!(config[..5], [9, CONFIGURATION, 84, 0, 3]);
    let full = control(&mut p, setup(0x80, GET_DESCRIPTOR, 0x200, 0, 255), &[]).unwrap();
    assert_eq!(full, configuration_descriptor(false));
    // The HID descriptors name each report descriptor's length.
    for (n, report) in [
        &KEYBOARD_REPORT_DESCRIPTOR[..],
        &POINTER_REPORT_DESCRIPTOR[..],
        &MOUSE_REPORT_DESCRIPTOR[..],
    ]
    .into_iter()
    .enumerate()
    {
        let hid = control(
            &mut p,
            setup(0x81, GET_DESCRIPTOR, 0x2100, n as u16, 9),
            &[],
        );
        assert_eq!(hid.unwrap()[7], report.len() as u8);
        let got = control(
            &mut p,
            setup(0x81, GET_DESCRIPTOR, 0x2200, n as u16, 255),
            &[],
        );
        assert_eq!(got.unwrap(), report);
    }
    let product = control(
        &mut p,
        setup(0x80, GET_DESCRIPTOR, 0x302, ENGLISH, 255),
        &[],
    );
    assert_eq!(product.unwrap()[0], 2 + 2 * 27);
    // The mouse is a boot mouse.
    assert_eq!(&full[59..68], &[9, 4, 2, 0, 1, 3, 1, 2, 0]);
    // A full-speed-only device STALLs the device qualifier.
    assert!(control(&mut p, setup(0x80, GET_DESCRIPTOR, 0x600, 0, 10), &[]).is_err());
    // A STALL clears at the next SETUP.
    assert!(control(&mut p, setup(0x80, GET_STATUS, 0, 0, 2), &[]).is_ok());
}

#[test]
fn a_system_control_interface_is_opt_in_and_sends_sleep_as_a_press_and_release() {
    // The default device has none: its fourth interface and endpoint stall.
    let mut plain = Peripheral::new();
    enumerate(&mut plain);
    assert!(control(&mut plain, setup(0x81, GET_DESCRIPTOR, 0x2200, 3, 255), &[]).is_err());
    assert_eq!(plain.packet(0x84, Token::In, &mut [0; 8]), Ok(Reply::Stall));
    assert!(plain.system_sleep().is_err());
    let mut p = Peripheral::with_system_control();
    let full = control(&mut p, setup(0x80, GET_DESCRIPTOR, 0x200, 0, 255), &[]).unwrap();
    assert_eq!(full[..5], [9, CONFIGURATION, 109, 0, 4]);
    // The keyboard and pointers are described as on the default device.
    assert_eq!(full[9..84], configuration_descriptor(false)[9..]);
    assert_eq!(full[84..93], [9, 4, 3, 0, 1, 3, 0, 0, 0]);
    assert_eq!(
        full[93..102],
        hid_descriptor(SYSTEM_REPORT_DESCRIPTOR.len())
    );
    assert_eq!(full[102..109], [7, 5, 0x84, 3, 1, 0, 1]);
    let report = control(&mut p, setup(0x81, GET_DESCRIPTOR, 0x2200, 3, 255), &[]).unwrap();
    assert_eq!(report, SYSTEM_REPORT_DESCRIPTOR);
    // Generic Desktop System Control, usages System Power Down to Wake Up.
    assert_eq!(
        report[..10],
        [0x05, 0x01, 0x09, 0x80, 0xa1, 0x01, 0x19, 0x81, 0x29, 0x83]
    );
    // Unconfigured, a request reaches nothing.
    p.system_sleep().unwrap();
    enumerate(&mut p);
    let mut packet = [0; 8];
    assert_eq!(p.packet(0x84, Token::In, &mut packet), Ok(Reply::Nak));
    p.system_sleep().unwrap();
    // Sleep (82h) is the second usage: pressed, then released.
    for expected in [0x02, 0x00] {
        assert_eq!(p.packet(0x84, Token::In, &mut packet), Ok(Reply::Ack(1)));
        assert_eq!(packet[0], expected);
    }
    assert_eq!(p.packet(0x84, Token::In, &mut packet), Ok(Reply::Nak));
    let current = control(&mut p, setup(0xa1, GET_REPORT, 0x100, 3, 1), &[]).unwrap();
    assert_eq!(current, [0]);
    // The keyboard still works beside it.
    p.input(Input::Key {
        usage: 0x04,
        pressed: true,
    })
    .unwrap();
    assert_eq!(p.packet(0x81, Token::In, &mut packet), Ok(Reply::Ack(8)));
    assert_eq!(packet[2], 0x04);
}

#[test]
fn configuration_needs_an_address_and_unconfigured_endpoints_stall() {
    let mut p = Peripheral::new();
    assert!(control(&mut p, setup(0, SET_CONFIGURATION, 1, 0, 0), &[]).is_err());
    let mut report = [0; 8];
    assert_eq!(p.packet(0x81, Token::In, &mut report), Ok(Reply::Stall));
    enumerate(&mut p);
    assert_eq!(p.packet(0x81, Token::In, &mut report), Ok(Reply::Nak));
    assert!(control(&mut p, setup(0, SET_ADDRESS, 4, 0, 0), &[]).is_err());
    assert!(control(&mut p, setup(0, SET_CONFIGURATION, 2, 0, 0), &[]).is_err());
    assert!(p.packet(1, Token::Setup, &mut [0; 8]).is_err());
}

#[test]
fn keys_and_motion_queue_reports() {
    let mut p = Peripheral::new();
    enumerate(&mut p);
    p.input(Input::Key {
        usage: 0xe1,
        pressed: true,
    })
    .unwrap();
    p.input(Input::Key {
        usage: 0x04,
        pressed: true,
    })
    .unwrap();
    assert_eq!(p.ready_at(0x81), Some(0));
    let mut report = [0; 8];
    assert_eq!(p.packet(0x81, Token::In, &mut report), Ok(Reply::Ack(8)));
    assert_eq!(report, [2, 0, 0, 0, 0, 0, 0, 0]);
    p.packet(0x81, Token::In, &mut report).unwrap();
    assert_eq!(report, [2, 0, 4, 0, 0, 0, 0, 0]);
    assert_eq!(p.ready_at(0x81), None);
    // Seven keys report rollover.
    for usage in 5..11 {
        p.input(Input::Key {
            usage,
            pressed: true,
        })
        .unwrap();
    }
    let mut last = [0; 8];
    while let Ok(Reply::Ack(_)) = p.packet(0x81, Token::In, &mut last) {}
    assert_eq!(last[2..], [ERROR_ROLLOVER; 6]);
    assert!(
        p.input(Input::Key {
            usage: 0x02,
            pressed: true
        })
        .is_err()
    );
    // Motion coalesces; a button change does not.
    p.input(Input::Move { x: 1, y: 2 }).unwrap();
    p.input(Input::Move { x: 0x7fff, y: 3 }).unwrap();
    p.input(Input::Buttons(1)).unwrap();
    p.input(Input::Wheel(-2)).unwrap();
    p.input(Input::HWheel(5)).unwrap();
    let mut pointer = [0; POINTER_REPORT];
    p.packet(0x82, Token::In, &mut pointer).unwrap();
    assert_eq!(pointer, [0, 0xff, 0x7f, 3, 0, 0, 0]);
    p.packet(0x82, Token::In, &mut pointer).unwrap();
    assert_eq!(pointer, [1, 0xff, 0x7f, 3, 0, 0, 0]);
    p.packet(0x82, Token::In, &mut pointer).unwrap();
    assert_eq!(pointer[5..], [(-2i8) as u8, 0]);
    p.packet(0x82, Token::In, &mut pointer).unwrap();
    assert_eq!(pointer[5..], [0, 5]);
    assert!(p.input(Input::Move { x: 0x8000, y: 0 }).is_err());
}

#[test]
fn mouse_motion_splits_coalesces_and_follows_the_protocol() {
    let mut p = Peripheral::new();
    enumerate(&mut p);
    let read = |p: &mut Peripheral| {
        let mut report = [0; MOUSE_REPORT];
        match p.packet(MOUSE_ENDPOINT, Token::In, &mut report).unwrap() {
            Reply::Ack(n) => Some(report[..n].to_vec()),
            _ => None,
        }
    };
    // 300 counts right split into 127 + 127 + 46; queued motion of the
    // same buttons coalesces.
    p.input(Input::Motion { dx: 300, dy: -5 }).unwrap();
    p.input(Input::Motion { dx: 10, dy: -5 }).unwrap();
    assert_eq!(p.ready_at(MOUSE_ENDPOINT), Some(0));
    assert_eq!(read(&mut p).unwrap(), [0, 127, (-5i8) as u8, 0, 0]);
    assert_eq!(read(&mut p).unwrap(), [0, 127, 0, 0, 0]);
    assert_eq!(read(&mut p).unwrap(), [0, 56, (-5i8) as u8, 0, 0]);
    assert_eq!(read(&mut p), None);
    // A button change and wheel motion each send a report.
    p.input(Input::MouseButtons(2)).unwrap();
    p.input(Input::Motion { dx: -1, dy: 1 }).unwrap();
    p.input(Input::MouseWheel(3)).unwrap();
    p.input(Input::MouseHWheel(-4)).unwrap();
    assert_eq!(read(&mut p).unwrap(), [2, (-1i8) as u8, 1, 0, 0]);
    assert_eq!(read(&mut p).unwrap(), [2, 0, 0, 3, 0]);
    assert_eq!(read(&mut p).unwrap(), [2, 0, 0, 0, (-4i8) as u8]);
    assert!(p.input(Input::MouseHWheel(i8::MIN)).is_err());
    assert!(p.input(Input::MouseButtons(8)).is_err());
    assert!(p.input(Input::MouseWheel(i8::MIN)).is_err());
    // The pointer's state is its own.
    assert_eq!(p.buttons, 0);
    // The boot protocol sends the three boot bytes.
    control(&mut p, setup(0x21, SET_PROTOCOL, 0, 2, 0), &[]).unwrap();
    p.input(Input::Motion { dx: 4, dy: 4 }).unwrap();
    assert_eq!(read(&mut p).unwrap(), [2, 4, 4]);
    let report = control(&mut p, setup(0xa1, GET_REPORT, 0x100, 2, 4), &[]).unwrap();
    assert_eq!(report, [2, 0, 0]);
    // The absolute pointer takes no protocol requests.
    assert!(control(&mut p, setup(0xa1, GET_PROTOCOL, 0, 1, 1), &[]).is_err());
}

#[test]
fn class_requests_set_leds_protocol_idle_and_halt() {
    let mut p = Peripheral::new();
    enumerate(&mut p);
    control(&mut p, setup(0x21, SET_REPORT, 0x200, 0, 1), &[0x23]).unwrap();
    assert_eq!(p.leds(), 3);
    control(&mut p, setup(0x21, SET_PROTOCOL, 0, 0, 0), &[]).unwrap();
    let protocol = control(&mut p, setup(0xa1, GET_PROTOCOL, 0, 0, 1), &[]).unwrap();
    assert_eq!(protocol, [BOOT_PROTOCOL]);
    assert!(control(&mut p, setup(0x21, SET_PROTOCOL, 0, 1, 0), &[]).is_err());
    let report = control(&mut p, setup(0xa1, GET_REPORT, 0x100, 1, 7), &[]).unwrap();
    assert_eq!(report.len(), POINTER_REPORT);
    // Any idle rate is acknowledged (DriverKit needs the status stage to
    // terminate its interfaces), but an unchanged report never repeats.
    control(&mut p, setup(0x21, SET_IDLE, 6 << 8, 0, 0), &[]).unwrap();
    control(&mut p, setup(0x21, SET_IDLE, 0, 0, 0), &[]).unwrap();
    assert_eq!(
        control(&mut p, setup(0xa1, GET_IDLE, 0, 0, 1), &[]).unwrap(),
        [0]
    );
    assert_eq!(p.ready_at(0x81), None);
    let mut buffer = [0; 8];
    assert_eq!(p.packet(0x81, Token::In, &mut buffer), Ok(Reply::Nak));
    // Halt and clear.
    control(&mut p, setup(0x02, SET_FEATURE, 0, 0x81, 0), &[]).unwrap();
    assert_eq!(p.packet(0x81, Token::In, &mut buffer), Ok(Reply::Stall));
    let status = control(&mut p, setup(0x82, GET_STATUS, 0, 0x81, 2), &[]).unwrap();
    assert_eq!(status, [1, 0]);
    control(&mut p, setup(0x02, CLEAR_FEATURE, 0, 0x81, 0), &[]).unwrap();
    assert_ne!(p.packet(0x81, Token::In, &mut buffer), Ok(Reply::Stall));
}

#[test]
fn a_nonzero_set_idle_reaches_its_status_stage() {
    let mut p = Peripheral::new();
    enumerate(&mut p);
    // macOS 26's DriverKit HID driver sends a nonzero idle rate. Stalling
    // it leaves three IOUSBHostInterface objects busy in kernelmanagerd,
    // which panics the guest 60 seconds into the userspace reboot.
    for interface in 0..INTERFACES {
        for rate in [1u16, 6, 0x14] {
            control(
                &mut p,
                setup(0x21, SET_IDLE, rate << 8, interface as u16, 0),
                &[],
            )
            .unwrap_or_else(|()| panic!("SET_IDLE rate {rate} stalled on interface {interface}"));
        }
    }
    // Keeping the request never promises idle repetitions.
    assert_eq!(
        control(&mut p, setup(0xa1, GET_IDLE, 0, 0, 1), &[]).unwrap(),
        [0]
    );
}

struct One(Peripheral);
impl Ports for One {
    fn count(&self) -> usize {
        1
    }
    fn speed(&self, _: usize) -> Speed {
        Speed::Full
    }
    fn function(&mut self, _: usize) -> &mut dyn Function {
        &mut self.0
    }
    fn function_ref(&self, _: usize) -> &dyn Function {
        &self.0
    }
}

/// Polls a host device makes for a report to arrive. The bench's controller
/// runs only when the driver touches a register, and the driver's owned
/// polls read only the event ring in memory until every 64th quiet look
/// samples the controller's status, so it takes that many more.
const POLLS: usize = 50 * 64;

#[test]
fn the_native_keyboard_and_pointer_reach_the_host_through_a_hub() {
    let hub = Hub::new(One(Peripheral::new()), "HUB").unwrap();
    let mut bench = host::bench(hub);
    let mut found = host::run(&mut bench);
    assert!(found.failures.is_empty(), "{:?}", found.failures);
    assert_eq!(found.inputs.len(), 3);
    let mut keyboard = found.inputs.remove(0);
    let mut pointer = found.inputs.remove(0);
    let mut mouse = found.inputs.remove(0);
    assert!(keyboard.poll().is_empty());
    assert!(pointer.poll().is_empty());
    assert!(mouse.poll().is_empty());
    let feed = |input: Input| {
        bench
            .model
            .borrow_mut()
            .function
            .ports
            .0
            .input(input)
            .unwrap();
    };
    feed(Input::Key {
        usage: 0x04,
        pressed: true,
    });
    feed(Input::Key {
        usage: 0xe1,
        pressed: true,
    });
    feed(Input::Move { x: 100, y: 0x7000 });
    feed(Input::Buttons(1));
    let mut keys = Vec::new();
    let mut motion = Vec::new();
    for _ in 0..POLLS {
        keys.extend(keyboard.poll());
        motion.extend(pointer.poll());
    }
    assert_eq!(
        keys,
        [
            Input::Key {
                usage: 0x04,
                pressed: true
            },
            Input::Key {
                usage: 0xe1,
                pressed: true
            },
        ]
    );
    assert!(
        motion.contains(&Input::Move { x: 100, y: 0x7000 }),
        "{motion:?}"
    );
    assert_eq!(motion.last(), Some(&Input::Buttons(1)));
    feed(Input::Key {
        usage: 0x04,
        pressed: false,
    });
    let mut released = Vec::new();
    for _ in 0..POLLS {
        released.extend(keyboard.poll());
    }
    assert_eq!(
        released,
        [Input::Key {
            usage: 0x04,
            pressed: false
        }]
    );
    // The native mouse runs the report protocol: its counts and wheel
    // arrive as they were sent.
    feed(Input::Motion { dx: -20, dy: 7 });
    feed(Input::MouseButtons(4));
    feed(Input::MouseWheel(-1));
    let mut moved = Vec::new();
    for _ in 0..POLLS {
        moved.extend(mouse.poll());
    }
    assert_eq!(
        moved,
        [
            Input::Motion { dx: -20, dy: 7 },
            Input::MouseButtons(4),
            Input::MouseWheel(-1),
        ]
    );
    assert!(!keyboard.failed() && !pointer.failed() && !mouse.failed());
}
