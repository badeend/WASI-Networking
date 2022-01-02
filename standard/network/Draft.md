# WASI Networking proposal

Please file an issue for comments, questions and additions.

## Goals

- Seek to find a sweet spot between the minimum amount of new API's and maximum compatibility with existing applications.
	- Based on abolutely no empirical evidence I'm going to assume that this should at least include the ability to do DNS lookups and create TCP clients. (although this proposal currently includes TCP servers & UDP sockets as well)
- POSIX compatibility wherever it makes sense.
- All functionality must be implementable on actively supported versions of major platforms:
	- Windows
	- Linux
	- *BSD
	- Mac OS
	- iOS
	- Android

## TODO

- DNS
- Async / nonblocking IO. I haven't added it yet, because I think there should be a generic WASM-wide solution for asynchronicity.
- Timeouts like `SO_RCVTIMEO` & `SO_SNDTIMEO`. See previous point. Preferably a generic mechanism for cancellation that can be applied to any async operation.
- Regarding `SO_REUSEADDR`, `SO_REUSEPORT`, `SO_REUSEPORT_LB` and `SO_EXCLUSIVEADDRUSE`:
	- Very useful functionality for server applications.
	- The compatibility story is, well... complicated.
	- These options specify how the WASM socket should interoperate with other (non-WASM) processes on the system. You could argue that these options operate on a conceptually higher level than the WASM module and thefore should be a concern of the WASI host instead of the module.
- Also, see the TODO comments sprinkled throughout the code below.

## Proposal spec

It has come to my attention that the current .witx specification is on its way out, so a Rust version is provided instead. There shouldn't be too many problems converting this to a future specification format when that time comes.

```rs

mod wasi_ephemeral_network {
    use crate::typenames::*;
    use crate::wasi_ephemeral_fd::Handle;


    /// Represents the ability to use the network.
    /// 
    /// This capability acts like a pseudo file descriptor.
    /// A capability handle can be closed using the regular `close(fd)` function.
    /// When this happens, the handle cannot be used to start make networking calls anymore.
    /// However, existing resources created through this handle will continue to work unaffected.
    /// 
    /// The "network" capability may seem overly broad. However, it is not all-or-nothing.
    /// It may be more appropiate to think of the "network" capability as an upper bound of permissions.
    /// A WASI runtime may choose to place more restrictions on a capability handle.
    /// For example: the host could construct a capability handle with which you can only create TCP connections on port 443.
    /// There is no way to query which of these restrictions have been applied from within a WASM module.
    /// The only thing a WASM module can do, is to just call the WASI functions it needs and see if they fail.
    /// 
    /// TODO: Not closing transitive resources transitive allows applications to harden their security.
    /// For example; a webserver can drop its own ability to start new listening sockets after initial setup.
    /// However, this most likely requires a way to drop capabilities only partially.
    /// Eg. drop the server-socket part, but keep the client-socket & dns parts.
    /// 
    /// TODO: This proposal doesn't mention how a wasm module should get a hold of a NetworkCapability,
    /// because this doesn't seem like a networking-specific problem.
    pub trait NetworkCapability
        : crate::wasi_ephemeral_fd::Handle
    {}


    /// Check to see if the provided handle is a network capability handle.
    ///
    /// Returns EBADF if the provided handle isn't a handle at all.
    pub fn is_network_capability(handle: &impl Handle) -> Expected<bool, errno> { todo!() }
}



mod wasi_ephemeral_sockets {
    use crate::typenames::*;
    use crate::wasi_ephemeral_fd::Handle;
    use crate::wasi_ephemeral_io_streams::{InputByteStream, OutputByteStream};
    use crate::wasi_ephemeral_network::NetworkCapability;


    /// Represents a socket file descriptor.
    /// 
    /// Sockets implement the input/output stream interfaces.
    /// That means you can use the regular `read`, `write`, etc functions on sockets.
    pub trait Socket
        : Handle
        + InputByteStream
        + OutputByteStream
    {}


    /// Create a new socket. Requires a network capability.
    /// 
    /// Only IPv4 and IPv6 are supported. IPv6 sockets returned by this function are never dualstack,
    /// because the POSIX `IPV6_V6ONLY = false` option can't be implemented in a cross platform manner.
    /// If you want to handle both IPv4 and IPv6 traffic, create two sockets; one for IPv4 traffic and one for IPv6 traffic.
    /// 
    /// FYI, IPV6_V6ONLY defaults per platform:
    /// - POSIX: default `false`
    /// - RFC3493: default `false`
    /// - Linux: default `false`, but some distros override this to `true`
    /// - Windows: default `true`
    /// - OpenBSD: always `true`, and can not be set to `false`.
    /// - FreeBSD: always `true`, and can only be set to `false` after a kernel config change.
    /// 
    /// TOOD: allow dualstack sockets, but opt-in and including a huge warning sticker?
    /// 
    /// There are only a handful of allowed `type` and `protocol` parameter combinations:
    /// 
    /// | `type`   | `protocol` | Result                |
    /// |----------|------------|-----------------------|
    /// | Stream   | None       | TCP                   |
    /// | Stream   | Some(Tcp)  | TCP                   |
    /// | Stream   | *          | EPROTONOSUPPORT error |
    /// | Datagram | None       | UDP                   |
    /// | Datagram | Some(Udp)  | UDP                   |
    /// | Datagram | *          | EPROTONOSUPPORT error |
    /// | *        | Some(Tcp)  | EPROTOTYPE error      |
    /// | *        | Some(Udp)  | EPROTOTYPE error      |
    /// | *        | *          | EPROTONOSUPPORT error |
    /// 
    /// # References:
    /// - https://pubs.opengroup.org/onlinepubs/9699919799/functions/socket.html
    /// - https://man7.org/linux/man-pages/man2/socket.2.html
    /// 
    pub async fn socket(
		network: &impl NetworkCapability,
		address_family: AddressFamily,
		r#type: SocketType,
		protocol: Option<SocketProtocol>
	) -> Expected<Box<dyn Socket>, errno> { todo!() }


	/// Bind the socket to a specific IP address and port.
	///
	/// If the IP address is zero (`0.0.0.0` in IPv4, `::` in IPv6), it is left to the implementation to decide which
    /// network interface(s) to bind to.
	/// If the TCP/UDP port is zero, the socket will be bound to a random free port.
	///
	/// TODO: Windows implementations should by default try to emulate UNIX behaviour by setting SO_EXCLUSIVEADDRUSE?
	///
    /// # References
    /// - https://pubs.opengroup.org/onlinepubs/9699919799/functions/bind.html
    /// - https://man7.org/linux/man-pages/man2/bind.2.html
	pub async fn bind(
		socket: &impl Socket,
		address: SocketAddress
	) -> Expected<(), errno> { todo!() }


    /// # References
    /// - https://pubs.opengroup.org/onlinepubs/9699919799/functions/listen.html
    /// - https://man7.org/linux/man-pages/man2/listen.2.html
	pub async fn listen(
		socket: &impl Socket,
		backlog_size_hint: Option<u32>
	) -> Expected<(), errno> { todo!() }


    /// Unlike POSIX, this function has no remote address out parameter.
    /// If you want to know this information, invoke `get_remote_address` on the newly created socket.
    /// 
    /// # References:
    /// - https://pubs.opengroup.org/onlinepubs/9699919799/functions/accept.html
    /// - https://man7.org/linux/man-pages/man2/accept.2.html
	pub async fn accept(
		socket: &impl Socket
		) -> Expected<Box<dyn Socket>, errno> { todo!() }


    /// # References
    /// - https://pubs.opengroup.org/onlinepubs/9699919799/functions/connect.html
    /// - https://man7.org/linux/man-pages/man2/connect.2.html
	pub async fn connect(
		socket: &impl Socket,
		address: SocketAddress
	) -> Expected<(), errno> { todo!() }


    /// # References
    /// - https://pubs.opengroup.org/onlinepubs/9699919799/functions/shutdown.html
    /// - https://man7.org/linux/man-pages/man2/shutdown.2.html
	pub async fn shutdown(
		socket: &impl Socket,
		shutdown_type: ShutdownType
	) -> Expected<(), errno> { todo!() }


    /// Receive a message.
    /// 
    /// Mostly interesting for datagram-oriented sockets like UDP.
    /// For TCP sockets you'll typically want to use `read(fd, ...)`.
    /// 
    /// Flags:
    /// - `peek`: Receive the message as usual, but don't remove the message from the queue.
    /// - `wait_all`: Try to read as much data as possible into the provided buffers
    ///     even if that means waiting while some initial data would already be readable otherwise.
    ///     This is opposite to the default behaviour where the `receive` call returns as soon as possible.
    ///     Note that this flag is only a hint. The implementation may choose to return before the entire buffer is filled.
    ///     Only supported on stream-oriented sockets.
    /// 
    /// Returns:
    /// - The number of bytes read.
    /// - If the received datagram was larger than the provided buffers,
    ///     the excess data is lost and the `truncated` flag will be set.
    ///     This never happens on Stream sockets.
    /// 
    /// `receive_from` additionally returns the sender address of the datagram or `None` for connection-oriented sockets.
    /// 
    /// TODO: iovec lengths are encoded as `usize` fields in UNIX, but `u32` in Windows regardless of OS-bitness.
    ///     Similarly, the number of bytes read in the return value is a `ssize` on UNIX, but `u32` on Windows.
    ///     Could be solved by silently capping the buffers at ssize::MAX before passing them to the native syscall?
    /// 
    /// # References
    /// - https://pubs.opengroup.org/onlinepubs/9699919799/functions/recv.html
    /// - https://pubs.opengroup.org/onlinepubs/9699919799/functions/recvfrom.html
    /// - https://pubs.opengroup.org/onlinepubs/9699919799/functions/recvmsg.html
    /// - https://man7.org/linux/man-pages/man2/recv.2.html
	pub async fn receive(
		socket: &impl Socket,
		iovs: &mut IovecArray,
		flags: ReceiveInputFlags
	) -> Expected<ReceiveOutput, errno> { todo!() }

	pub async fn receive_from(
		socket: &impl Socket,
		iovs: &mut IovecArray,
		flags: ReceiveInputFlags
	) -> Expected<ReceiveFromOutput, errno> { todo!() }
    

    /// Send a message.
    /// 
    /// Mostly interesting for datagram-oriented sockets like UDP.
    /// For TCP sockets you'll typically want to use `write(fd, ...)`.
    /// 
    /// Returns the number of bytes sent.
    /// 
    /// `send_to` additionally takes a destination address.
    /// 
    /// # References
    /// - https://pubs.opengroup.org/onlinepubs/9699919799/functions/send.html
    /// - https://pubs.opengroup.org/onlinepubs/9699919799/functions/sendto.html
    /// - https://pubs.opengroup.org/onlinepubs/9699919799/functions/sendmsg.html
    /// - https://man7.org/linux/man-pages/man2/send.2.html
    pub async fn send(
		socket: &impl Socket,
		iovs: &mut IovecArray,
		flags: SendInputFlags
	) -> Expected<usize, errno> { todo!() }

    pub async fn send_to(
		socket: &impl Socket,
		iovs: &mut IovecArray,
		flags: SendInputFlags,
		destination: SocketAddress
	) -> Expected<usize, errno> { todo!() }


    /// # References
    /// - https://pubs.opengroup.org/onlinepubs/9699919799/functions/getpeername.html
    /// - https://man7.org/linux/man-pages/man2/getpeername.2.html
	pub fn get_remote_address(
		socket: &impl Socket
	) -> Expected<SocketAddress, errno> { todo!() }


    /// # References
    /// - https://pubs.opengroup.org/onlinepubs/9699919799/functions/getsockname.html
    /// - https://man7.org/linux/man-pages/man2/getsockname.2.html
    pub fn get_local_address(
		socket: &impl Socket
	) -> Expected<SocketAddress, errno> { todo!() }

    /// Buffer size.
    /// 
    /// The default value is implementation-dependent.
    /// When the implementation deems the requested size too small or too large,
    /// it may silently clamp the value or return an error.
    /// 
    /// TODO: investigate how existing platforms handle invalid values.
    ///     -> Windows allows any u32 value, all the way from 0 to u32::MAX.
    /// 
    /// Similar to `sockopt(socket, SOL_SOCKET, SO_RCVBUF/SO_SNDBUF, ...)` in POSIX.
    /// 
    ///  # References
    /// - https://pubs.opengroup.org/onlinepubs/9699919799/functions/V2_chap02.html
    /// - https://man7.org/linux/man-pages/man7/socket.7.html
    /// - https://www.freebsd.org/cgi/man.cgi?query=setsockopt&apropos=0&sektion=0&manpath=FreeBSD+14.0-current&arch=default&format=html
    /// - https://docs.microsoft.com/en-us/windows/win32/winsock/sol-socket-socket-options
    pub fn set_receive_buffer_size(
		socket: &impl Socket,
		size: u32
	) -> Expected<(), errno> { todo!() }
	
    pub fn get_receive_buffer_size(
		socket: &impl Socket
	) -> Expected<u32, errno> { todo!() }

    pub fn set_send_buffer_size(
		socket: &impl Socket,
		size: u32
	) -> Expected<(), errno> { todo!() }

    pub fn get_send_buffer_size(
		socket: &impl Socket
	) -> Expected<u32, errno> { todo!() }

    /// Disable the Nagle algorithm.
    /// 
    /// By default nodelay is turned off.
    /// 
    /// Similar to `get/setsockopt(socket, IPPROTO_TCP, TCP_NODELAY, ...)` in POSIX.
    /// 
    /// # References
    /// - https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/netinet_tcp.h.html
    /// - https://man7.org/linux/man-pages/man7/tcp.7.html
    pub fn set_tcp_nodelay(
		socket: &impl Socket,
		enable_nodelay: bool
	) -> Expected<(), errno>{ todo!() }

    pub fn get_tcp_nodelay(
		socket: &impl Socket
	) -> Expected<bool, errno> { todo!() }






	/* ACCOMPANYING DATATYPES: */




    pub type Ipv4Address = [u8; 4];
    pub type Ipv6Address = [u8; 16];

    pub struct Ipv4SocketAddress {
        port: u16, // sin_port
        address: Ipv4Address, // sin_addr
    }

    pub struct Ipv6SocketAddress {
        port: u16, // sin6_port
        flowinfo: u32, // sin6_flowinfo
        address: Ipv6Address, // sin6_addr
        scope_id: u32, // sin6_scope_id
    }

    // struct UnixSocketAddress {
    //     path: String, // sun_path.
    // }

    pub enum SocketAddress {
        Ipv4(Ipv4SocketAddress),
        Ipv6(Ipv6SocketAddress),
        // Unix(UnixSocketAddress),
    }

    /// Unpacked form of the `flags` bitfield parameter.
    pub struct ReceiveInputFlags {
        peek: bool, // MSG_PEEK
        wait_all: bool, // MSG_WAITALL

        // Not implemented:
        // MSG_OOB
        // MSG_CMSG_CLOEXEC (Not in POSIX)
        // MSG_DONTWAIT (Not in POSIX)
        // MSG_ERRQUEUE (Not in POSIX)
    }

    /// Unpacked form of the `msghdr->msg_flags` bitfield member.
    pub struct ReceiveOutputFlags {
        truncated: bool, // MSG_TRUNC
        
        // Not implemented:
        // MSG_EOR
        // MSG_OOB
        // MSG_CTRUNC
        // MSG_ERRQUEUE (Not in POSIX)
    }

    pub struct ReceiveOutput {
        bytes_received: usize,
        flags: ReceiveOutputFlags,
    }

    pub struct ReceiveFromOutput {
        bytes_received: usize,
        flags: ReceiveOutputFlags,
        address: Option<SocketAddress>,
    }

    /// Unpacked form of the `flags` bitfield parameter.
    pub struct SendInputFlags {
        // Not implemented:
        // MSG_EOR
        // MSG_OOB
        // MSG_NOSIGNAL
        // MSG_MORE (Not in POSIX)
        // MSG_DONTWAIT (Not in POSIX)
        // MSG_DONTROUTE (Not in POSIX)
        // MSG_CONFIRM (Not in POSIX)
    }

    pub enum ShutdownType { // Possible alternative names for "type": Component, Side, Part
        Receive, // SHUT_RD. Shutdown for further reading/receiving
        Send, // SHUT_WR. Shutdown for further writing/sending
        Both, // SHUT_RDWR. Shutdown for further reading/receiving & writing/sending
    }

    pub enum SocketType {
        Stream, // SOCK_STREAM
        Datagram, // SOCK_DGRAM

        // Not implemented:
        // SOCK_SEQPACKET
        // SOCK_RAW
    }

    pub enum SocketProtocol {
        Tcp, // IPPROTO_TCP
        Udp, // IPPROTO_UDP

        // See also: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
    }

    pub enum AddressFamily {
        Ipv4, // AF_INET
        Ipv6, // AF_INET6

        // Not implemented:
		// AF_UNIX / AF_LOCAL
        // AF_ALG
        // AF_APPLETALK
        // AF_ASH
        // AF_ATMPVC
        // AF_ATMSVC
        // AF_AX25
        // AF_BLUETOOTH
        // AF_BRIDGE
        // AF_CAIF
        // AF_CAN
        // AF_DECnet
        // AF_ECONET
        // AF_IB
        // AF_IEEE802154
        // AF_IPX
        // AF_IRDA
        // AF_ISDN
        // AF_IUCV
        // AF_KCM
        // AF_KEY
        // AF_LLC
        // AF_MPLS
        // AF_NETBEUI
        // AF_NETLINK
        // AF_NETROM
        // AF_PACKET
        // AF_PHONET
        // AF_PPPOX
        // AF_QIPCRTR
        // AF_RDS
        // AF_ROSE
        // AF_ROUTE
        // AF_RXRPC
        // AF_SECURITY
        // AF_SMC
        // AF_SNA
        // AF_TIPC
        // AF_UNSPEC
        // AF_VSOCK
        // AF_WANPIPE
        // AF_X25
        // AF_XDP
        // ...
    }
}









/* STUBS OF EXISTING WASI PROPOSALS & WASM INTERFACE TYPES: */


mod typenames {
    pub type List<T> = Vec<T>;
    pub enum Expected<TOk, TError>
    {
        Ok(TOk),
        Error(TError),
    }

    pub type Iovec = List<u8>;
    pub type IovecArray = List<Iovec>;

    pub enum errno { /* ... */ }

}

// https://github.com/WebAssembly/wasi-handle-index
mod wasi_ephemeral_fd {
    pub trait Handle {}

    pub async fn close(handle: &impl Handle) { unimplemented!() }
}

// https://github.com/WebAssembly/wasi-io
mod wasi_ephemeral_io_streams {
    use crate::typenames::*;

    pub trait InputByteStream {}
    pub trait OutputByteStream {}


    pub async fn read(input_stream: &impl InputByteStream, iovs: &mut IovecArray) { unimplemented!() }
    pub async fn write(output_stream: &impl OutputByteStream, iovs: &mut IovecArray) { unimplemented!() }
    pub async fn flush(output_stream: &impl OutputByteStream) { unimplemented!() }
    // ...
}

```