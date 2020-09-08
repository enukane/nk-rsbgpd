#![allow(dead_code)]

use std::net::{TcpListener, TcpStream, SocketAddr};
use std::io::{Read, Write};
use std::thread;
use std::mem;
use std::net::{Ipv4Addr};

/* params */
const MY_IPV4_ADDR: &str = "10.10.10.10";
const MY_AS:u16 = 65001;
const MY_BGP_VER:u8 = 4;
const MY_HOLD_TIME:u16 = 120;


/* bgp header => 19 byte  */
#[repr(C, packed)]
struct BGPHeader {
    bh_marker: u128,
    bh_len: u16,
    bh_type: u8
}

#[derive(PartialEq)]
enum BGPType{
    Open = 1,
    Update = 2,
    Notification = 3,
    KeepAlive = 4,
}

#[repr(C, packed)]
struct BGPOpenMsg {
    version: u8,
    my_as: u16,
    hold_time: u16,
    bgp_id: u32,
    bgp_optlen: u8
    /* option follows */
}

#[repr(C, packed)]
struct BGPNotificationMsg {
    error_code: u8,
    error_subcode: u8
    /* data follows */
}

enum BGPErrorCode {
    MessageHeaderError = 1,
    OPENMessageError = 2,
    UPDATEMessageError = 3,
    HoldTimerExpired = 4,
    FiniteStateMachineError = 5,
    Cease = 6
}

enum BGPErrorSubCodeMessageHeaderError {
    ConnectionNotSynced = 1,
    BadMessageLength = 2,
    BadMessageType = 3
}

//https://www.iana.org/assignments/capability-codes/capability-codes.xhtml
enum BGPCapabilityCodes {
    MultiprotoExtensionsForBGP4 = 1,
    RouteRefreshCapforBGP4 = 2,
    OutboundRouteFilteringCap = 3,
    ExtendedNextHopEncoding = 5,
    BGPExtendedMessage = 6,
    BGPsecCap = 7,
    MultiLabelsCap = 8,
    BGPRole = 9,

    GradefulRestartCap = 64,
    Support4OctetAS = 65,
    SupportDynamicCap = 67,
    MultisessionBGPCap = 68,
    ADDPATHCap = 69,
    EnhancedRouteRefreshCap = 70,
    LLGRCap = 71,
    RoutingPolicyDistribution = 72,
    FQDNCap = 73
}

// yes of cource, we live in little endian world
fn ntohs(num: u16) -> u16 {
    ((num & 0xff) << 8) | ((num >> 8) & 0xff)
}

fn htons(num: u16) -> u16 {
    ((num & 0xff00) >> 8) | (num & 0xff) << 8
}

fn ntohl(num: u32) -> u32 {
    println!("ntohl 0x{:x}", num);
    let mut tmp = num;
    let mut val = 0;
    for i in 0..4 {
        if i != 0 {
            val = val << 8;
            tmp = tmp >> 8;
        }
        val += tmp & 0xff;
    }
    val
}

fn htonl(num: u32) -> u32 {
    let mut tmp = num;
    let mut val = 0;
    for i in 0..4 {
        if i != 0 {
            val = val << 8;
            tmp = tmp >> 8;
        }
        val += tmp & 0xff;
    }
    val
}

unsafe fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
    ::std::slice::from_raw_parts((p as *const T) as *const u8,
        ::std::mem::size_of::<T>(),
    )
}

fn handle_bgp_capability(ary: Vec<u8>) {
    let ary_len = ary.len();
    let code = ary[0];
    let len = ary[1];
    let left_ary = &ary[2..ary_len];
}

fn handle_bgp_open_params(bgp_open_params: &[u8], params_len: usize) {
    // param_type u8, length u8, data [u8]
    let mut i = 0;
    loop {
        if i >= params_len {
            break;
        }

        let param_type: u8 = bgp_open_params[i];
        i+=1;
        let param_len: u8 = bgp_open_params[i];
        i+=1;
        let mut param_data = Vec::<u8>::new();

        if param_len > 0 {
            for j in 0..param_len {
                param_data.push(bgp_open_params[i+(j as usize)]);
            }
            i += param_len as usize;
        }

        println!("  BGP Open Option: Type {} Length {} Data {:?}", param_type, param_len, param_data);
    };
}

fn handle_bgp_open<'a> (bgp_msg: &[u8], msg_len: usize, resp_bgp_buf: &mut [u8]) -> (bool, BGPType, usize) {
    println!("BGP Open");

    let bgp_open_msg_len = std::mem::size_of::<BGPOpenMsg>();
    assert_eq!(bgp_open_msg_len <= msg_len, true, "buffer too small to be open msg");

    let (_head, body, _tail) = unsafe { bgp_msg.align_to::<BGPOpenMsg>() };
    let bgp_open_msg = &body[0];
    println!("BGPOpen: version = {},  = {}, hold_time = {}, bgp_id = 0x{:08x}, ip_optlen = {}",
            bgp_open_msg.version, ntohs(bgp_open_msg.my_as),
            ntohs(bgp_open_msg.hold_time), ntohl(bgp_open_msg.bgp_id),
            bgp_open_msg.bgp_optlen);

    if bgp_open_msg.bgp_optlen > 0 {
        handle_bgp_open_params(&bgp_msg[bgp_open_msg_len..msg_len], msg_len - bgp_open_msg_len);
    }

    let mut resp_bgp_open_msg = BGPOpenMsg {
        version: 0,
        my_as: 0,
        hold_time: 0,
        bgp_id: 0,
        bgp_optlen: 0
    };
    resp_bgp_open_msg.version = MY_BGP_VER;
    resp_bgp_open_msg.my_as = htons(MY_AS);
    resp_bgp_open_msg.hold_time = htons(MY_HOLD_TIME);
    let addr: Ipv4Addr = MY_IPV4_ADDR.parse().unwrap();
    resp_bgp_open_msg.bgp_id = htonl(u32::from(addr));
    resp_bgp_open_msg.bgp_optlen = 0;
    let bgp_buf = unsafe {any_as_u8_slice(&resp_bgp_open_msg)};

    resp_bgp_buf[0..bgp_open_msg_len].copy_from_slice(bgp_buf);

    (false, BGPType::Open, bgp_open_msg_len)
}

fn handle_bgp_keepalive(_bgp_msg: &[u8], _msg_len: usize, _resp_bgp_buf: &mut [u8]) -> (bool, BGPType, usize) {
    println!("BGP KeepAlive");
    (false, BGPType::KeepAlive, 0)
}

fn handle_error_type(bgp_type: u8, resp_bgp_buf: &mut [u8], resp_bgp_buf_len: usize) -> (bool, BGPType, usize) {
    println!("unknown type: {}", bgp_type);
    let bgp_notif_buf_len = std::mem::size_of::<BGPNotificationMsg>();
    let resp_bgp_notif_msg = BGPNotificationMsg {
        error_code: BGPErrorCode::MessageHeaderError as u8,
        error_subcode: BGPErrorSubCodeMessageHeaderError::BadMessageType as u8
    };

    if bgp_notif_buf_len > resp_bgp_buf_len {
        println!("Error: handle_error_type: not enough buffer");
        return (true, BGPType::Notification, 0)
    }
    let bgp_buf = unsafe { any_as_u8_slice(&resp_bgp_notif_msg) };
    resp_bgp_buf[0..bgp_notif_buf_len].copy_from_slice(bgp_buf);

    (true, BGPType::Notification, bgp_notif_buf_len)
}

fn generate_notification(error_code: BGPErrorSubCodeMessageHeaderError, error_subcode: u8, data_buf: &[u8], data_len: usize, buf: &mut [u8], buf_len: usize) -> Result(usize) {
    let bgp_notif_buf_len = std::mem::size_of::<BGPNotificationMsg>();
    let tot_len = bgp_notif_buf_len + data_len;
    if tot_len > buf_len {
        printnt!("Error: generate_notification: not enough buffer");
        return Err(-1);

    }

    let resp_bgp_notif_msg = BGPNotificationMsg {
        error_code: error_code as u8,
        error_subcode: error_subcode as u8
    }

    let notif_msg_buf = unsafe { any_as_u8_slice(&resp_bgp_notif_msg) };
    resp_bgp_buf[0..bgp_notif_buf_len].copy_from_slice(notif_msg_buf);
    resp_bgp_buf[bgp_notif_buf_len..bgp_notif_buf_len+data_len].copy_from_slice(data_buf[0..data_len]);

    return Ok(tot_len);
}

fn handle_protocol(peer: SocketAddr, buf: &[u8], len: usize, resp_buf: &mut [u8], resp_buf_len: usize) -> (bool, usize) {
    println!("[{}] handle_protocol {} first {}", peer, len, buf[0]);

    let (head, body, _tail) = unsafe { buf.align_to::<BGPHeader>() };
    assert!(head.is_empty(), "Data was not aligned");

    let bgp_header_len = mem::size_of::<BGPHeader>();

    let bgp_header = &body[0];
    let bgp_marker = bgp_header.bh_marker;
    let bgp_len = ntohs(bgp_header.bh_len);
    let bgp_type = bgp_header.bh_type;
    println!("received BGP message: marker 0x{:x}, len {}, type {}", bgp_marker, bgp_len, bgp_type);

    let bgp_msg = &buf[bgp_header_len..];
    let left_len = len - (bgp_header_len);

    let mut resp_bgp_header = BGPHeader {
        bh_marker: 0xffffffffffffffffffffffffffffffff as u128, //sorry! we dont ntoh
        bh_len: bgp_header_len as u16,
        bh_type: BGPType::Open as u8
    };

    let mut resp_bgp_body_buf = [0u8; 1024];
    let (is_close, resp_type, resp_body_len) = if bgp_type == BGPType::Open as u8 {
        handle_bgp_open(bgp_msg, left_len, &mut resp_bgp_body_buf)
    } else if bgp_type == BGPType::Update as u8 {
        handle_bgp_open()
//    } else if bgp_type == BGPType::Notification as u8 {
//        // TBD
    } else if bgp_type == BGPType::KeepAlive as u8 {
        handle_bgp_keepalive(bgp_msg, left_len, &mut resp_bgp_body_buf)
    } else {
        handle_error_type(bgp_type, &mut resp_bgp_body_buf, 1024)
    };
    //println!("body len = {}, body = 0x{:02x}", resp_body_len, resp_bgp_body_buf[0]);

    if resp_body_len == 0 && resp_type != BGPType::KeepAlive {
        /* response nothing */
        return (is_close, 0)
    }

    // header copy
    let total_len: u16 = resp_bgp_header.bh_len + resp_body_len as u16;
    resp_bgp_header.bh_type = resp_type as u8;
    resp_bgp_header.bh_len = htons(total_len);
    println!("Resp Type => #{}", resp_bgp_header.bh_type);
    let bgp_header_buf = unsafe { any_as_u8_slice(&resp_bgp_header)};

    if bgp_header_len >= resp_buf_len {
        println!("Error: handle_protocol overruns buffer: header {} > allocated {}", bgp_header_len, resp_buf_len);
        return (true, 0)
    }
    resp_buf[..bgp_header_len].copy_from_slice(bgp_header_buf);

    if bgp_header_len+resp_body_len >= resp_buf_len {
        println!("Error: handle_protocol overruns buffer: header+body {} > allocated {}", bgp_header_len, resp_buf_len);
        return (true, 0)
    }

    resp_buf[bgp_header_len..(bgp_header_len + resp_body_len)].copy_from_slice(&resp_bgp_body_buf[..resp_body_len]);

    return (is_close, total_len as usize)
}

fn handle_client(mut stream: TcpStream) {
    let mut buf = [0; 1024];

    loop {
        let len = stream.read(&mut buf).unwrap();
        if len == 0 {
            break;
        }

        println!("[{}] received {} bytes", stream.peer_addr().unwrap(), len);

        let mut resp_buf = [0u8; 1024];
        let (is_close, resp_buf_len) = handle_protocol(stream.peer_addr().unwrap(), &buf, len, &mut resp_buf, 1024);

        if !resp_buf_len > 0 {
            match stream.write(&resp_buf[..(resp_buf_len)]) {
                Ok(len) => {
                    println!("[{}] write {} bytes", stream.peer_addr().unwrap(), len);
                },
                Err(e) => {
                    println!("Error: IO error write {}", e);
                }
            }
            //stream.flush();
        }

        if is_close == true {
            break;
        }

    };
    println!("closed connection: {}", stream.peer_addr().unwrap());
}

fn main() {
    let listener = TcpListener::bind("0.0.0.0:179").unwrap();
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                println!("New connection: {}", stream.peer_addr().unwrap());
                thread::spawn(move|| {
                    handle_client(stream)
                });
            },
            Err(e) => {
                println!("Error connection: {}", e);

            }
        };
    };
    //drop(listener);
}