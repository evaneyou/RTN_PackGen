//! Per-packet DSCP/TOS: read the marking of received datagrams and send datagrams with a given
//! marking from a shared socket. Linux only; elsewhere reads report `None` and writes are unmarked.

use std::io;
use std::net::SocketAddr;

use tokio::net::UdpSocket;

/// Ask the kernel to deliver the TOS / traffic class of incoming datagrams. Best effort.
pub(crate) fn enable_recv_tos(sock: &UdpSocket) {
    #[cfg(target_os = "linux")]
    imp::enable_recv_tos(sock);
    #[cfg(not(target_os = "linux"))]
    let _ = sock;
}

/// `recv_from` that also returns the datagram's TOS byte when the kernel provides it.
pub(crate) async fn recv_from(
    sock: &UdpSocket,
    buf: &mut [u8],
) -> io::Result<(usize, SocketAddr, Option<u8>)> {
    #[cfg(target_os = "linux")]
    return imp::recv_from(sock, buf).await;
    #[cfg(not(target_os = "linux"))]
    return sock.recv_from(buf).await.map(|(n, peer)| (n, peer, None));
}

/// `send_to` with an explicit TOS byte for this datagram only (other users of the socket keep
/// their own marking).
pub(crate) async fn send_to(
    sock: &UdpSocket,
    buf: &[u8],
    dest: SocketAddr,
    tos: Option<u8>,
) -> io::Result<usize> {
    #[cfg(target_os = "linux")]
    if let Some(t) = tos {
        return imp::send_to(sock, buf, dest, t).await;
    }
    let _ = tos;
    sock.send_to(buf, dest).await
}

#[cfg(target_os = "linux")]
mod imp {
    use std::io;
    use std::mem::{size_of, zeroed};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::os::fd::AsRawFd;

    use tokio::io::Interest;
    use tokio::net::UdpSocket;

    pub fn enable_recv_tos(sock: &UdpSocket) {
        let fd = sock.as_raw_fd();
        let on: libc::c_int = 1;
        let p = &on as *const libc::c_int as *const libc::c_void;
        let len = size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: valid fd and a pointer to a live c_int of the stated length.
        unsafe {
            libc::setsockopt(fd, libc::IPPROTO_IP, libc::IP_RECVTOS, p, len);
            libc::setsockopt(fd, libc::IPPROTO_IPV6, libc::IPV6_RECVTCLASS, p, len);
        }
    }

    fn to_socket_addr(ss: &libc::sockaddr_storage) -> Option<SocketAddr> {
        match ss.ss_family as libc::c_int {
            libc::AF_INET => {
                // SAFETY: the family says this storage holds a sockaddr_in.
                let a = unsafe { &*(ss as *const _ as *const libc::sockaddr_in) };
                Some(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr))),
                    u16::from_be(a.sin_port),
                ))
            }
            libc::AF_INET6 => {
                // SAFETY: as above, for sockaddr_in6.
                let a = unsafe { &*(ss as *const _ as *const libc::sockaddr_in6) };
                Some(SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::from(a.sin6_addr.s6_addr)),
                    u16::from_be(a.sin6_port),
                ))
            }
            _ => None,
        }
    }

    fn recvmsg_once(fd: i32, buf: &mut [u8]) -> io::Result<(usize, SocketAddr, Option<u8>)> {
        // SAFETY: every pointer handed to recvmsg points into locals that outlive the call, and
        // the control buffer is 8-byte aligned as cmsghdr requires.
        unsafe {
            let mut name: libc::sockaddr_storage = zeroed();
            let mut iov = libc::iovec {
                iov_base: buf.as_mut_ptr() as *mut libc::c_void,
                iov_len: buf.len(),
            };
            let mut control = [0u64; 8];
            let mut msg: libc::msghdr = zeroed();
            msg.msg_name = &mut name as *mut _ as *mut libc::c_void;
            msg.msg_namelen = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
            msg.msg_controllen = size_of_val(&control) as _;
            let n = libc::recvmsg(fd, &mut msg, 0);
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            let mut tos = None;
            let mut c = libc::CMSG_FIRSTHDR(&msg);
            while !c.is_null() {
                let h = &*c;
                let data = libc::CMSG_DATA(c);
                if h.cmsg_level == libc::IPPROTO_IP && h.cmsg_type == libc::IP_TOS {
                    tos = Some(*data);
                } else if h.cmsg_level == libc::IPPROTO_IPV6 && h.cmsg_type == libc::IPV6_TCLASS {
                    tos = Some(std::ptr::read_unaligned(data as *const libc::c_int) as u8);
                }
                c = libc::CMSG_NXTHDR(&msg, c);
            }
            let peer = to_socket_addr(&name)
                .ok_or_else(|| io::Error::other("datagram from an unsupported address family"))?;
            Ok((n as usize, peer, tos))
        }
    }

    pub async fn recv_from(
        sock: &UdpSocket,
        buf: &mut [u8],
    ) -> io::Result<(usize, SocketAddr, Option<u8>)> {
        let fd = sock.as_raw_fd();
        sock.async_io(Interest::READABLE, || recvmsg_once(fd, buf))
            .await
    }

    fn sendmsg_once(fd: i32, buf: &[u8], dest: SocketAddr, tos: u8) -> io::Result<usize> {
        // SAFETY: as in recvmsg_once; the destination and control buffers outlive the call.
        unsafe {
            let mut name: libc::sockaddr_storage = zeroed();
            let namelen = match dest {
                SocketAddr::V4(a) => {
                    let s = &mut name as *mut _ as *mut libc::sockaddr_in;
                    (*s).sin_family = libc::AF_INET as _;
                    (*s).sin_port = a.port().to_be();
                    (*s).sin_addr.s_addr = u32::from(*a.ip()).to_be();
                    size_of::<libc::sockaddr_in>()
                }
                SocketAddr::V6(a) => {
                    let s = &mut name as *mut _ as *mut libc::sockaddr_in6;
                    (*s).sin6_family = libc::AF_INET6 as _;
                    (*s).sin6_port = a.port().to_be();
                    (*s).sin6_addr.s6_addr = a.ip().octets();
                    (*s).sin6_flowinfo = a.flowinfo();
                    (*s).sin6_scope_id = a.scope_id();
                    size_of::<libc::sockaddr_in6>()
                }
            };
            let mut iov = libc::iovec {
                iov_base: buf.as_ptr() as *mut libc::c_void,
                iov_len: buf.len(),
            };
            let mut control = [0u64; 8];
            let mut msg: libc::msghdr = zeroed();
            msg.msg_name = &mut name as *mut _ as *mut libc::c_void;
            msg.msg_namelen = namelen as libc::socklen_t;
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
            let (level, kind, payload_len) = if dest.is_ipv4() {
                (libc::IPPROTO_IP, libc::IP_TOS, size_of::<u8>())
            } else {
                (
                    libc::IPPROTO_IPV6,
                    libc::IPV6_TCLASS,
                    size_of::<libc::c_int>(),
                )
            };
            msg.msg_controllen = libc::CMSG_SPACE(payload_len as u32) as _;
            let c = libc::CMSG_FIRSTHDR(&msg);
            (*c).cmsg_level = level;
            (*c).cmsg_type = kind;
            (*c).cmsg_len = libc::CMSG_LEN(payload_len as u32) as _;
            if dest.is_ipv4() {
                *libc::CMSG_DATA(c) = tos;
            } else {
                std::ptr::write_unaligned(libc::CMSG_DATA(c) as *mut libc::c_int, tos as _);
            }
            let n = libc::sendmsg(fd, &msg, 0);
            if n < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        }
    }

    pub async fn send_to(
        sock: &UdpSocket,
        buf: &[u8],
        dest: SocketAddr,
        tos: u8,
    ) -> io::Result<usize> {
        let fd = sock.as_raw_fd();
        sock.async_io(Interest::WRITABLE, || sendmsg_once(fd, buf, dest, tos))
            .await
    }
}
