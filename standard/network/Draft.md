# WASI Networking proposal

Please file an issue for comments, questions and additions.

### Table of contents
- [Goals](#goals)
- [Dualstack](#dualstack)
- [Notable omissions](#omissions)
- [TODO](#todo)
- [Proposal spec](#spec)
- [POSIX compatibility](#posix-compatibility)
- [Security](#security)


## Goals
<a name="goals"></a>

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

## Dualstack
<a name="dualstack"></a>

IPv6 sockets returned by this proposal are never dualstack because that can't be implemented in a cross platform manner. If an application wants to serve both IPv4 and IPv6 traffic, it should create two sockets; one for IPv4 traffic and one for IPv6 traffic.

Dualstack support per platform according to the internet: (Not verified)
- OpenBSD: Not supported.
- FreeBSD: Not supported by default, but support can be manually toggled with a system-wide config change.
- Windows: Supported. Disabled by default. Can be enabled on a per-socket basis.
- Linux: Supported. Generally enabled by default, but some distros disable it by default.
- POSIX & RFC3493: Specifies IPv6 sockets should be dualstack by default.

## Notable omissions
<a name="omissions"></a>

- Checks for IPv4 & IPv6 support of the host.
- getnameinfo
- gethostname
- rescvmsg/sendmsg with cmsg / ancillary data
- ioctl(fd, FIONREAD, ...)
- Network interface enumeration
- Anything higher level than sockets; TLS/SSL, HTTP, ...
- The many, _many_ socket options. Some thoughts on specific options:
    - `SO_REUSEADDR`, `SO_REUSEPORT`, `SO_REUSEPORT_LB` and `SO_EXCLUSIVEADDRUSE`:
        - A must-have for many applications.
        - The portability story is, well... complicated.
        - These options specify how the WASM socket should interoperate with other (non-WASM) processes on the system. One could argue that these options operate on a conceptually higher level than the WASM module and thefore should be a concern of the WASI host instead being dictated by a module.
    - `SO_RCVTIMEO` & `SO_SNDTIMEO`:
        - I would prefer a generic WASM-wide solution for cancellation that can be applied to any async operation.

## TODO
<a name="todo"></a>

- Async / nonblocking IO.
- Allow dualstack sockets, but opt-in and including a huge warning sticker?
- Should Windows implementations try to emulate UNIX behaviour by setting SO_EXCLUSIVEADDRUSE by default?
- iovec lengths are encoded as `usize` fields in UNIX, but `u32` in Windows regardless of OS-bitness. Similarly, the number of bytes read in the return value of recv is a `ssize` on UNIX, but `u32` on Windows. Could be solved by silently capping the buffers at ssize::MAX before passing them to the native syscall?
- This proposal doesn't mention (yet) how a wasm module should get a hold of the capability handles (IpAddressResolver, UdpCapableNetwork, TcpCapableNetwork).
- Also, see the TODO comments sprinkled throughout the code below.

## Proposal spec
<a name="spec"></a>

It has come to my attention that the current .witx specification is on its way out, so a Rust version is provided instead. There shouldn't be too many problems converting this to a future specification format when that time comes.

In the Rust example code below, socket state transitions are modeled by swallowing the original value and returning the same socket wrapped inside a new type. Effectively a poor man's sessions types. These are just to clarify the semantics, they are not intended to end up in the final WIT spec.


```rs

pub mod new_typenames {

    #[non_exhaustive] // TODO: https://github.com/WebAssembly/interface-types/issues/145
    pub enum SocketProtocol {
        Tcp,
        Udp,
        // ...
    }

    pub enum IpAddressFamily {
        Ipv4, // AF_INET
        Ipv6, // AF_INET6
    }

    pub struct Ipv4Address {
        address: [u8; 4], // TODO: https://github.com/WebAssembly/interface-types/issues/146
    }
    pub struct Ipv6Address {
        address: [u8; 16], // TODO: https://github.com/WebAssembly/interface-types/issues/146
        scope_id: u32,
    }

    pub enum IpAddress {
        Ipv4(Ipv4Address),
        Ipv6(Ipv6Address),
    }

    pub struct Ipv4SocketAddress {
        port: u16, // sin_port
        address: Ipv4Address, // sin_addr
    }

    pub struct Ipv6SocketAddress {
        port: u16, // sin6_port
        flowinfo: u32, // sin6_flowinfo
        address: Ipv6Address, // sin6_addr
    }

    pub enum IpSocketAddress {
        Ipv4(Ipv4SocketAddress),
        Ipv6(Ipv6SocketAddress),
    }

    pub struct UdpReceiveResult {
        bytes_received: usize,
        truncated: bool, // MSG_TRUNC
    }

    pub struct UdpReceiveFromResult {
        bytes_received: usize,
        truncated: bool, // MSG_TRUNC
        address: IpSocketAddress,
    }

    pub enum TcpShutdownType {
        Receive, // SHUT_RD
        Send, // SHUT_WR
        Both, // SHUT_RDWR
    }
}



/// Functions applicable to all sockets.
pub mod socket {
    use crate::new_typenames::*;
    use crate::wasi_ephemeral_fd::*;

    pub trait Socket : Handle + Sized {
        fn protocol(&self) -> SocketProtocol;
    }
}



/// Functions applicable to Internet sockets. This for example excludes UNIX sockets.
pub mod socket_ip {
    use crate::new_typenames::*;
    use crate::socket::*;

    pub trait IpSocket : Socket {
        fn address_family(&self) -> IpAddressFamily;
    }
}



/// UDP sockets MVP.
pub mod socket_udp {
    use crate::typenames::*;
    use crate::new_typenames::*;
    use crate::socket_ip::*;
    use crate::wasi_ephemeral_io_streams::*;

    pub trait UdpCapableNetwork {
        type UdpSocket: UdpSocket;

        /// Create a new UDP socket.
        /// 
        /// Similar to `socket(AF_INET or AF_INET6, SOCK_DGRAM, IPPROTO_UDP)` in POSIX.
        /// 
        /// # References:
        /// - https://pubs.opengroup.org/onlinepubs/9699919799/functions/socket.html
        /// - https://man7.org/linux/man-pages/man2/socket.2.html
        /// 
        fn create_udp_socket(&self, address_family: IpAddressFamily) -> Self::UdpSocket;
    }

    pub trait UdpSocket : IpSocket {
        type UdpConnectionSocket : UdpConnectionSocket;

        /// Bind the socket to a specific IP address and port.
        ///
        /// If the IP address is zero (`0.0.0.0` in IPv4, `::` in IPv6), it is left to the implementation to decide which
        /// network interface(s) to bind to.
        /// If the TCP/UDP port is zero, the socket will be bound to a random free port.
        /// 
        /// When a socket is not explicitly bound, the first invocation to a send or receive operation will
        /// implicitly bind the socket.
        /// 
        /// Returns an error if the socket is already bound.
        /// 
        /// # References
        /// - https://pubs.opengroup.org/onlinepubs/9699919799/functions/bind.html
        /// - https://man7.org/linux/man-pages/man2/bind.2.html
        fn bind(&self, local_address: IpSocketAddress) -> Result<(), errno>;

        /// Get the current bound address.
        /// 
        /// Returns an error if the socket is not bound.
        /// 
        /// # References
        /// - https://pubs.opengroup.org/onlinepubs/9699919799/functions/getsockname.html
        /// - https://man7.org/linux/man-pages/man2/getsockname.2.html
        fn local_address(&self) -> Result<IpSocketAddress, errno>;

        /// Receive a message.
        /// 
        /// Returns:
        /// - The sender address of the datagram
        /// - The number of bytes read.
        /// - When the received datagram is larger than the provided buffers,
        ///     the excess data is lost and the `truncated` flag will be set.
        /// 
        /// # References
        /// - https://pubs.opengroup.org/onlinepubs/9699919799/functions/recvfrom.html
        /// - https://pubs.opengroup.org/onlinepubs/9699919799/functions/recvmsg.html
        /// - https://man7.org/linux/man-pages/man2/recv.2.html
        fn receive_from(&self, iovs: &mut IovecArray) -> Result<UdpReceiveFromResult, errno>;

        /// Receive a message just like `receive_from`, but don't remove the message from the queue.
        fn peek_from(&self, iovs: &mut IovecArray) -> Result<UdpReceiveFromResult, errno>;

        /// Send a message to a specific destination address.
        /// 
        /// Returns the number of bytes sent.
        /// 
        /// TODO: Does the returned number of bytes sent ever differ from the supplied buffer size for UDP sockets?
        /// 
        /// # References
        /// - https://pubs.opengroup.org/onlinepubs/9699919799/functions/sendto.html
        /// - https://pubs.opengroup.org/onlinepubs/9699919799/functions/sendmsg.html
        /// - https://man7.org/linux/man-pages/man2/send.2.html
        fn send_to(&self, iovs: &IovecArray, remote_address: IpSocketAddress) -> Result<usize, errno>;

        /// Set the destination address.
        /// 
        /// When a destination address is set:
        /// - all receive operations will only return datagrams sent from the provided `remote_address`.
        /// - the `send` function will use this remote_address.
        /// - the `send_to` function can still be used to send to any other destination, however you can't receive their response.
        /// 
        /// Similar to `connect(sock, ...)` in POSIX.
        /// 
        /// Note that this function does not generate any network traffic and the peer is not aware of this "connection".
        /// 
        /// TODO: "connect" is a rather odd name for this function because it doesn't reflect what's actually happening.
        ///     Feels like it was chosen just to shoehorn UDP into the existing Socket interface.
        ///     Do we have to keep this name?
        /// 
        /// # References
        /// - https://pubs.opengroup.org/onlinepubs/9699919799/functions/connect.html
        /// - https://man7.org/linux/man-pages/man2/connect.2.html
        fn connect(self, remote_address: IpSocketAddress) -> Result<Self::UdpConnectionSocket, (Self, errno)>;
    }

    pub trait UdpConnectionSocket : UdpSocket + InputByteStream + OutputByteStream {

        /// Receive a message from the address set with `connect`.
        /// 
        /// Returns:
        /// - The number of bytes read.
        /// - If the received datagram was larger than the provided buffers,
        ///     the excess data is lost and the `truncated` flag will be set.
        /// 
        /// # References
        /// - https://pubs.opengroup.org/onlinepubs/9699919799/functions/recv.html
        /// - https://pubs.opengroup.org/onlinepubs/9699919799/functions/recvmsg.html
        /// - https://man7.org/linux/man-pages/man2/recv.2.html
        fn receive(&self, iovs: &mut IovecArray) -> Result<UdpReceiveResult, errno>;

        /// Receive a message just like `receive`, but don't remove the message from the queue.
        fn peek(&self, iovs: &mut IovecArray) -> Result<UdpReceiveResult, errno>;

        /// Send a message to the address set with `connect`.
        /// 
        /// Returns the number of bytes sent.
        /// 
        /// # References
        /// - https://pubs.opengroup.org/onlinepubs/9699919799/functions/send.html
        /// - https://pubs.opengroup.org/onlinepubs/9699919799/functions/sendmsg.html
        /// - https://man7.org/linux/man-pages/man2/send.2.html
        fn send(&self, iovs: &IovecArray) -> Result<usize, errno>;

        /// Get the address set with `connect`.
        /// 
        /// # References
        /// - https://pubs.opengroup.org/onlinepubs/9699919799/functions/getpeername.html
        /// - https://man7.org/linux/man-pages/man2/getpeername.2.html
        fn remote_address(&self) -> Result<IpSocketAddress, errno>;
    }
}



/// TCP sockets MVP.
pub mod socket_tcp {
    use crate::typenames::*;
    use crate::new_typenames::*;
    use crate::socket_ip::*;
    use crate::wasi_ephemeral_io_streams::*;

    pub trait TcpCapableNetwork {
        type TcpIndeterminateSocket: TcpIndeterminateSocket;

        /// Create a new TCP socket.
        /// 
        /// Similar to `socket(AF_INET or AF_INET6, SOCK_STREAM, IPPROTO_TCP)` in POSIX.
        /// 
        /// # References:
        /// - https://pubs.opengroup.org/onlinepubs/9699919799/functions/socket.html
        /// - https://man7.org/linux/man-pages/man2/socket.2.html
        /// 
        fn create_tcp_socket(&self, address_family: IpAddressFamily) -> Self::TcpIndeterminateSocket;
    }

    pub trait TcpSocket : IpSocket {

        /// Bind the socket to a specific IP address and port.
        ///
        /// If the IP address is zero (`0.0.0.0` in IPv4, `::` in IPv6), it is left to the implementation to decide which
        /// network interface(s) to bind to.
        /// If the TCP/UDP port is zero, the socket will be bound to a random free port.
        /// 
        /// When a socket is not explicitly bound, the first invocation to a listen or connect operation will
        /// implicitly bind the socket.
        /// 
        /// Returns an error if the socket is already bound.
        /// 
        /// # References
        /// - https://pubs.opengroup.org/onlinepubs/9699919799/functions/bind.html
        /// - https://man7.org/linux/man-pages/man2/bind.2.html
        fn bind(&self, local_address: IpSocketAddress) -> Result<(), errno>;

        /// Get the current bound address.
        /// 
        /// Returns an error if the socket is not bound.
        /// 
        /// # References
        /// - https://pubs.opengroup.org/onlinepubs/9699919799/functions/getsockname.html
        /// - https://man7.org/linux/man-pages/man2/getsockname.2.html
        fn local_address(&self) -> Result<IpSocketAddress, errno>;
    }

    pub trait TcpIndeterminateSocket : TcpSocket {
        type TcpClientSocket : TcpConnectionSocket;
        type TcpServerSocket : TcpServerSocket;

        /// # References
        /// - https://pubs.opengroup.org/onlinepubs/9699919799/functions/connect.html
        /// - https://man7.org/linux/man-pages/man2/connect.2.html
        fn connect(self, remote_address: IpSocketAddress) -> Result<Self::TcpClientSocket, (Self, errno)>;

        /// # References
        /// - https://pubs.opengroup.org/onlinepubs/9699919799/functions/listen.html
        /// - https://man7.org/linux/man-pages/man2/listen.2.html
        fn listen(self, backlog_size_hint: Option<u32>) -> Result<Self::TcpServerSocket, (Self, errno)>;
    }

    pub trait TcpConnectionSocket : TcpSocket + InputByteStream + OutputByteStream {

        /// Read data from the stream just like `InputByteStream::read`, but don't remove the data from the queue.
        fn peek(&self, iovs: &mut IovecArray) -> Result<usize, errno>;

        /// # References
        /// - https://pubs.opengroup.org/onlinepubs/9699919799/functions/getpeername.html
        /// - https://man7.org/linux/man-pages/man2/getpeername.2.html
        fn remote_address(&self) -> Result<IpSocketAddress, errno>;
        
        /// Gracefully shut down the connection.
        /// 
        /// - Receive: the socket is not expecting to receive any more data from the peer. All subsequent read/receive
        ///   operations will return 0, indicating End Of Stream. If there is still data in the receive queue at time of
        ///   calling `shutdown` or whenever new data arrives afterwards, then (TODO).
        /// - Send: the socket is not expecting to send any more data to the peer. After all data in the send queue has
        ///   been sent and acknowledged, a FIN will be sent. All subsequent write/send operations will return an
        ///   EPIPE error.
        /// - Both: Receive & Send
        /// 
        /// The shutdown function does not close the socket.
        /// 
        /// TODO: Look into how different platforms behave after shutdown(Read) has been called and new data arrives. According to the internet (unverified):
        /// - BSD: silently discards the data
        /// - Linux: effectively ignores the shutdown call. New data can still be read. If not done will ultimately block the sender.
        /// - Windows: sends RST
        /// 
        /// # References
        /// - https://pubs.opengroup.org/onlinepubs/9699919799/functions/shutdown.html
        /// - https://man7.org/linux/man-pages/man2/shutdown.2.html
        fn shutdown(&self, shutdown_type: TcpShutdownType) -> Result<(), errno>;
    }

    pub trait TcpServerSocket : TcpSocket {
        type TcpServerAcceptedSocket : TcpConnectionSocket;

        /// Unlike POSIX, this function does not returns the remote address.
        /// If you want to know this information, invoke `get_remote_address` on the newly created socket.
        /// 
        /// # References:
        /// - https://pubs.opengroup.org/onlinepubs/9699919799/functions/accept.html
        /// - https://man7.org/linux/man-pages/man2/accept.2.html
        fn accept(&self) -> Result<Self::TcpServerAcceptedSocket, errno>;
    }
}



pub mod ip_resolve_address {
    use crate::typenames::*;
    use crate::new_typenames::*;

    pub trait IpAddressResolver {

        /// Resolve an internet host name to a list of IP addresses.
        /// 
        /// # Parameters:
        /// - `name`: The name to look up. If this is an IP address in string form, the address is deserialized and
        ///   returned without making any network calls.
        /// - `address_family`: If provided, limit the results to addresses of this specific address family.
        /// - `include_unavailable`: When set to true, this function will also return addresses of which the runtime
        ///   thinks (or knows) can't be connected to at the moment. For example, this will return IPv6 addresses on
        ///   systems without an active IPv6 interface. Notes:
        ///     - Even when no public IPv6 interfaces are present or active, names like "localhost" can still resolve to an IPv6 address.
        ///     - Whatever is "available" or "unavailable" is volatile and can change everytime a network cable is unplugged.
        /// 
        /// # Results:
        /// - When successful, there is always at least one result.
        /// - The results are returned in the order the runtime thinks the application should try to connect to first.
        /// - Never returns IPv4-mapped IPv6 addresses.
        /// 
        /// 
        /// # Comparison with getaddrinfo:
        /// 
        /// `getaddrinfo` is very generic and multipurpose by design. This WASI module is *not*.
        /// This module focuses strictly on translating internet domain names to ip addresses.
        /// That eliminates many of the other "hats" getaddrinfo has, like:
        /// - Mapping service names to port numbers ("https" -> 443)
        /// - Mapping service names/ports to socket types ("https" -> SOCK_STREAM)
        /// - IP address string canonicalization
        /// - Constants lookup for INADDR_ANY, INADDR_LOOPBACK, IN6ADDR_ANY_INIT & IN6ADDR_LOOPBACK_INIT
        /// 
        /// Although not actually verified, I think most or all of these functionalities can shimmed in the libc implementation.
        /// 
        /// This function has a different signature and semantics than `getaddrinfo`. The dissimilar name is chosen to reflect this.
        /// 
        /// TODO: Can resolve_addresses be (ab)used to enumerate the installed network interfaces?
        /// 
        /// # References:
        /// - https://pubs.opengroup.org/onlinepubs/9699919799/functions/getaddrinfo.html
        /// - https://man7.org/linux/man-pages/man3/getaddrinfo.3.html
        /// 
        fn resolve_addresses(&self, name: String, address_family: Option<IpAddressFamily>, include_unavailable: bool) -> Result<Vec<IpAddress>, errno>;
    }
}








/* STUBS OF EXISTING WASI PROPOSALS & WASM INTERFACE TYPES: */


mod typenames {
    pub type Iovec = Vec<u8>;
    pub type IovecArray = Vec<Iovec>;

    pub enum errno { /* ... */ }

}

// https://github.com/WebAssembly/wasi-handle-index
mod wasi_ephemeral_fd {
    use crate::typenames::*;

    pub trait Handle {
        fn close(&self) -> Result<(), errno>;
    }
}

// https://github.com/WebAssembly/wasi-io
mod wasi_ephemeral_io_streams {
    use crate::typenames::*;

    pub trait InputByteStream {
        fn read(&self, iovs: &mut IovecArray) -> Result<usize, errno>;
        // ...
    }
    
    pub trait OutputByteStream {
        fn write(&self, iovs: &IovecArray) -> Result<usize, errno>;
        fn flush(&self) -> Result<(), errno>;
        // ...
    }
}

```


## POSIX compatibility
<a name="posix-compatibility"></a>

The modules proposed above do not form a POSIX compatible interface. Functions have been split up into multiple functions to increase modularity, and parameters & flags that did not apply within a specific context have been dropped.

Nevertheless, if everything goes according to plan, a POSIX compatible layer can be built on top of it in wasi-libc. Some pseudo code to get the idea across:

```rs
fn socket(address_family: i32, socket_type: i32, protocol: i32) {

    let ambient_network_capability = // Pluck it out of thin air.

    match (socket_type, protocol) {
        (SOCK_STREAM, 0) | (SOCK_STREAM, IPPROTO_TCP) => wasi_socket_tcp::create_tcp_socket(ambient_network_capability, address_family),
        (SOCK_DGRAM, 0) | (SOCK_DGRAM, IPPROTO_UDP) => wasi_socket_udp::create_udp_socket(ambient_network_capability, address_family),
        _ => EINVAL,
    }
}

fn recvfrom(socket: i32, flags: i32) {
    
    let protocol = wasi_socket::protocol(socket);
    let peek = flags & MSG_PEEK;

    match (protocol, peek) {
        (Udp, false) => wasi_socket_udp::receive_from(socket),
        (Udp, true) => wasi_socket_udp::peek_from(socket),
        (Tcp, false) => (wasi_io_streams::read(socket), address: unspecified, truncated: false),
        (Tcp, true) => (wasi_socket_tcp::peek(socket), address: unspecified, truncated: false),
        _ => EBADF,
    }
}

fn getsockopt(socket: i32, level: i32, optname: i32) {

    let protocol = wasi_socket::protocol(socket);

    match (level, optname) {
        (SOL_SOCKET, SO_PROTOCOL) => protocol,

        (SOL_SOCKET, SO_TYPE) => match protocol {
            Protocol::Tcp -> SOCK_STREAM,
            Protocol::Udp -> SOCK_DGRAM,
        },

        (SOL_SOCKET, SO_DOMAIN) => match protocol {
            Protocol::Tcp | Protocol::Udp -> wasi_socket_ip::address_family(socket),
        },

        // ....

        _ => EINVAL,
    }
}
```

## Security
<a name="security"></a>

Wasm modules can not open sockets by themselves without somehow having acquired the ability to do so (UdpCapableNetwork, TcpCapableNetwork). This allows some interesting workflows:
- Passing a prebound listening socket to the wasm module, letting the module only accept and handle new connections. Leaving the socket setup to the implementation.
- Passing an already connected socket to the wasm module, letting the module only handle that specific connection. This can be useful in scenarios where the implementation wants to spin up a wasm module per request.

Even with capability handles, WASI implementations should deny all network access by default. Access should be granted at the most granular level possible. Whenever access is denied, the implementation should return EACCES.

This means Wasm modules will get a lot more EACCES errors compared to when running unsandboxed. This might break existing applications that, for example, don't expect running a TCP client to require special permissions.

At the moment there is no way for a Wasm modules to query which network access permissions it has. The only thing it can do, is to just call the WASI functions it needs and see if they fail.

### Granting access:

This section is mostly here to indicate the granularity of permissions that ought to be possible. It is by no means a recommendation of any kind. It's just spitballing how a CLI-based implementation might grant access.


```shell

# Allow the lookup of a specific domain name
--allow-resolve=example.com

# Allow the lookup of all subdomains
--allow-resolve=*.example.com

# Allow any lookup
--allow-resolve=*

# Only look up IPv4 addresses
--allow-resolve=example.com#ipv4-only

# Only look up IPv6 addresses
--allow-resolve=example.com#ipv6-only




# Allow TCP connections to 127.0.0.1 on port 80
--allow-outbound=tcp://127.0.0.1:80

# Allow TCP connections to 127.0.0.1 on any port
--allow-outbound=tcp://127.0.0.1:*

# Allow TCP connections to any server on port 80
--allow-outbound=tcp://*:80

# Allow TCP connections to any IP address resolved from `example.com` on port 80. This also implies `--allow-resolve=example.com`
--allow-outbound=tcp://example.com:80

# Allow all TCP connections
--allow-outbound=tcp://*:*

# Allow TCP connection with IPv4 only
--allow-outbound=tcp://...#ipv4-only

# Allow TCP connection with IPv6 only
--allow-outbound=tcp://...#ipv6-only

# Allow TCP connections to a specific list of ports
--allow-outbound=tcp://*:80,443

# Allow TCP connections to a range of ports
--allow-outbound=tcp://*:21,35000-35999

# Allow UDP client
--allow-outbound=udp://...




# Allow listening only on loopback interfaces on port 80
--allow-inbound=tcp://localhost:80

# Allow listening on a specific network interface on port 80
--allow-inbound=tcp://eth0:80

# Allow listening on any network interface on port 80
--allow-inbound=tcp://*:80

# Allow listening on a randomly generated port
--allow-inbound=tcp://*:0

```

### Virtualization / mapping:

Just like wasmtime already has the ability to remap directories with `--mapdir`, similar constructs can be conceived for networking. Examples:

_Again: not an official recommendation of any kind._

```shell

# Map a domain name resolvable from within the wasm module to an IP address.
--allow-resolve=my-database.internal->172.17.0.14

# Allow listening to TCP port 80 inside the wasm module, which is mapped to port 8888 on the host.
--allow-inbound=tcp://*:80->8888

# Allow TCP connections to any IP address resolved from `my-database.internal` which is mapped to `172.17.0.14` on
# port 5432 which is mapped to 5433. This also implies `--allow-resolve=my-database.internal->172.17.0.14`
--allow-outbound=tcp://my-database.internal->172.17.0.14:5432->5433

```