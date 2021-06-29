// Copyright (C) 2020, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#[macro_use]
extern crate log;

use std::cmp;

use std::io;

use std::net;

use std::io::prelude::*;

use std::collections::HashMap;

use std::rc::Rc;

use std::cell::RefCell;

use ring::rand::*;

use quiche_apps::args::*;

use quiche_apps::common::*;

const MAX_BUF_SIZE: usize = 65536;

const MAX_DATAGRAM_SIZE: usize = 1350;

const MAX_SEND_BURST_PACKETS: usize = 10;

fn main() {
    let mut buf = [0; MAX_BUF_SIZE];
    let mut out = [0; MAX_BUF_SIZE];

    env_logger::builder()
        .default_format_timestamp_nanos(true)
        .init();

    // Parse CLI parameters.
    let docopt = docopt::Docopt::new(SERVER_USAGE).unwrap();
    let conn_args = CommonArgs::with_docopt(&docopt);
    let args = ServerArgs::with_docopt(&docopt);

    // Setup the event loop.
    let poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);

    // Create the UDP listening socket, and register it with the event loop.
    let socket = net::UdpSocket::bind(args.listen).unwrap();

    info!("listening on {:}", socket.local_addr().unwrap());

    let socket = mio::net::UdpSocket::from_socket(socket).unwrap();
    poll.register(
        &socket,
        mio::Token(0),
        mio::Ready::readable(),
        mio::PollOpt::edge(),
    )
    .unwrap();

    let max_datagram_size = MAX_DATAGRAM_SIZE;
    let enable_gso = detect_gso(&socket, max_datagram_size);

    trace!("GSO detected: {}", enable_gso);

    // Create the configuration for the QUIC connections.
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();

    config.load_cert_chain_from_pem_file(&args.cert).unwrap();
    config.load_priv_key_from_pem_file(&args.key).unwrap();

    config.set_application_protos(&conn_args.alpns).unwrap();

    config.set_max_idle_timeout(conn_args.idle_timeout);
    config.set_max_recv_udp_payload_size(max_datagram_size);
    config.set_max_send_udp_payload_size(max_datagram_size);
    config.set_initial_max_data(conn_args.max_data);
    config.set_initial_max_stream_data_bidi_local(conn_args.max_stream_data);
    config.set_initial_max_stream_data_bidi_remote(conn_args.max_stream_data);
    config.set_initial_max_stream_data_uni(conn_args.max_stream_data);
    config.set_initial_max_streams_bidi(conn_args.max_streams_bidi);
    config.set_initial_max_streams_uni(conn_args.max_streams_uni);
    config.set_disable_active_migration(true);

    let mut keylog = None;

    if let Some(keylog_path) = std::env::var_os("SSLKEYLOGFILE") {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(keylog_path)
            .unwrap();

        keylog = Some(file);

        config.log_keys();
    }

    if conn_args.early_data {
        config.enable_early_data();
    }

    if conn_args.no_grease {
        config.grease(false);
    }

    config
        .set_cc_algorithm_name(&conn_args.cc_algorithm)
        .unwrap();

    if conn_args.disable_hystart {
        config.enable_hystart(false);
    }

    if conn_args.dgrams_enabled {
        config.enable_dgram(true, 1000, 1000);
    }

    let rng = SystemRandom::new();
    let conn_id_seed =
        ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng).unwrap();

    let mut clients = ClientMap::new();

    let mut pkt_count = 0;

    let mut continue_write = false;

    loop {
        // Find the shorter timeout from all the active connections.
        //
        // TODO: use event loop that properly supports timers
        let timeout = match continue_write {
            true => Some(std::time::Duration::from_secs(0)),

            false => clients.values().filter_map(|c| c.conn.timeout()).min(),
        };

        poll.poll(&mut events, timeout).unwrap();

        // Read incoming UDP packets from the socket and feed them to quiche,
        // until there are no more packets to read.
        'read: loop {
            // If the event loop reported no events, it means that the timeout
            // has expired, so handle it without attempting to read packets. We
            // will then proceed with the send loop.
            if events.is_empty() && !continue_write {
                trace!("timed out");

                clients.values_mut().for_each(|c| c.conn.on_timeout());

                break 'read;
            }

            let (len, from) = match socket.recv_from(&mut buf) {
                Ok(v) => v,

                Err(e) => {
                    // There are no more UDP packets to read, so end the read
                    // loop.
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        trace!("recv() would block");
                        break 'read;
                    }

                    panic!("recv() failed: {:?}", e);
                },
            };

            trace!("got {} bytes", len);

            let pkt_buf = &mut buf[..len];

            if let Some(target_path) = conn_args.dump_packet_path.as_ref() {
                let path = format!("{}/{}.pkt", target_path, pkt_count);

                if let Ok(f) = std::fs::File::create(&path) {
                    let mut f = std::io::BufWriter::new(f);
                    f.write_all(pkt_buf).ok();
                }
            }

            pkt_count += 1;

            // Parse the QUIC packet's header.
            let hdr = match quiche::Header::from_slice(
                pkt_buf,
                quiche::MAX_CONN_ID_LEN,
            ) {
                Ok(v) => v,

                Err(e) => {
                    error!("Parsing packet header failed: {:?}", e);
                    continue 'read;
                },
            };

            trace!("got packet {:?}", hdr);

            let conn_id = ring::hmac::sign(&conn_id_seed, &hdr.dcid);
            let conn_id = &conn_id.as_ref()[..quiche::MAX_CONN_ID_LEN];
            let conn_id = conn_id.to_vec().into();

            // Lookup a connection based on the packet's connection ID. If there
            // is no connection matching, create a new one.
            let client = if !clients.contains_key(&hdr.dcid) &&
                !clients.contains_key(&conn_id)
            {
                if hdr.ty != quiche::Type::Initial {
                    error!("Packet is not Initial");
                    continue 'read;
                }

                if !quiche::version_is_supported(hdr.version) {
                    warn!("Doing version negotiation");

                    let len =
                        quiche::negotiate_version(&hdr.scid, &hdr.dcid, &mut out)
                            .unwrap();

                    let out = &out[..len];

                    if let Err(e) = socket.send_to(out, &from) {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            trace!("send() would block");
                            break;
                        }

                        panic!("send() failed: {:?}", e);
                    }
                    continue 'read;
                }

                let mut scid = [0; quiche::MAX_CONN_ID_LEN];
                scid.copy_from_slice(&conn_id);

                let mut odcid = None;

                if !args.no_retry {
                    // Token is always present in Initial packets.
                    let token = hdr.token.as_ref().unwrap();

                    // Do stateless retry if the client didn't send a token.
                    if token.is_empty() {
                        warn!("Doing stateless retry");

                        let scid = quiche::ConnectionId::from_ref(&scid);
                        let new_token = mint_token(&hdr, &from);

                        let len = quiche::retry(
                            &hdr.scid,
                            &hdr.dcid,
                            &scid,
                            &new_token,
                            hdr.version,
                            &mut out,
                        )
                        .unwrap();

                        let out = &out[..len];

                        if let Err(e) = socket.send_to(out, &from) {
                            if e.kind() == std::io::ErrorKind::WouldBlock {
                                trace!("send() would block");
                                break;
                            }

                            panic!("send() failed: {:?}", e);
                        }
                        continue 'read;
                    }

                    odcid = validate_token(&from, token);

                    // The token was not valid, meaning the retry failed, so
                    // drop the packet.
                    if odcid.is_none() {
                        error!("Invalid address validation token");
                        continue;
                    }

                    if scid.len() != hdr.dcid.len() {
                        error!("Invalid destination connection ID");
                        continue 'read;
                    }

                    // Reuse the source connection ID we sent in the Retry
                    // packet, instead of changing it again.
                    scid.copy_from_slice(&hdr.dcid);
                }

                let scid = quiche::ConnectionId::from_vec(scid.to_vec());

                debug!("New connection: dcid={:?} scid={:?}", hdr.dcid, scid);

                #[allow(unused_mut)]
                let mut conn =
                    quiche::accept(&scid, odcid.as_ref(), from, &mut config)
                        .unwrap();

                if let Some(keylog) = &mut keylog {
                    if let Ok(keylog) = keylog.try_clone() {
                        conn.set_keylog(Box::new(keylog));
                    }
                }

                // Only bother with qlog if the user specified it.
                #[cfg(feature = "qlog")]
                {
                    if let Some(dir) = std::env::var_os("QLOGDIR") {
                        let id = format!("{:?}", &scid);
                        let writer = make_qlog_writer(&dir, "server", &id);

                        conn.set_qlog(
                            std::boxed::Box::new(writer),
                            "quiche-server qlog".to_string(),
                            format!("{} id={}", "quiche-server qlog", id),
                        );
                    }
                }

                let client = Client {
                    conn,
                    http_conn: None,
                    partial_requests: HashMap::new(),
                    partial_responses: HashMap::new(),
                    siduck_conn: None,
                    app_proto_selected: false,
                    bytes_sent: 0,
                    max_datagram_size,
                    max_send_burst: cmp::min(
                        MAX_BUF_SIZE,
                        max_datagram_size * MAX_SEND_BURST_PACKETS,
                    ),
                };

                clients.insert(scid.clone(), client);

                clients.get_mut(&scid).unwrap()
            } else {
                match clients.get_mut(&hdr.dcid) {
                    Some(v) => v,

                    None => clients.get_mut(&conn_id).unwrap(),
                }
            };

            let recv_info = quiche::RecvInfo { from };

            // Process potentially coalesced packets.
            let read = match client.conn.recv(pkt_buf, recv_info) {
                Ok(v) => v,

                Err(e) => {
                    error!("{} recv failed: {:?}", client.conn.trace_id(), e);
                    continue 'read;
                },
            };

            trace!("{} processed {} bytes", client.conn.trace_id(), read);

            // Create a new application protocol session as soon as the QUIC
            // connection is established.
            if !client.app_proto_selected &&
                (client.conn.is_in_early_data() ||
                    client.conn.is_established())
            {
                // At this stage the ALPN negotiation succeeded and selected a
                // single application protocol name. We'll use this to construct
                // the correct type of HttpConn but `application_proto()`
                // returns a slice, so we have to convert it to a str in order
                // to compare to our lists of protocols. We `unwrap()` because
                // we need the value and if something fails at this stage, there
                // is not much anyone can do to recover.
                let app_proto = client.conn.application_proto();
                let app_proto = &std::str::from_utf8(&app_proto).unwrap();

                if alpns::HTTP_09.contains(app_proto) {
                    client.http_conn = Some(Box::new(Http09Conn::default()));

                    client.app_proto_selected = true;
                } else if alpns::HTTP_3.contains(app_proto) {
                    let dgram_sender = if conn_args.dgrams_enabled {
                        Some(Http3DgramSender::new(
                            conn_args.dgram_count,
                            conn_args.dgram_data.clone(),
                            1,
                        ))
                    } else {
                        None
                    };

                    client.http_conn = Some(Http3Conn::with_conn(
                        &mut client.conn,
                        dgram_sender,
                        Rc::new(RefCell::new(stdout_sink)),
                    ));

                    client.app_proto_selected = true;
                } else if alpns::SIDUCK.contains(app_proto) {
                    client.siduck_conn = Some(SiDuckConn::new(
                        conn_args.dgram_count,
                        conn_args.dgram_data.clone(),
                    ));

                    client.app_proto_selected = true;
                }

                // Update max_datagram_size after connection established.
                client.max_datagram_size =
                    client.conn.max_send_udp_payload_size();
                client.max_send_burst = cmp::min(
                    MAX_BUF_SIZE,
                    client.max_datagram_size * MAX_SEND_BURST_PACKETS,
                );
            }

            if client.http_conn.is_some() {
                let conn = &mut client.conn;
                let http_conn = client.http_conn.as_mut().unwrap();
                let partial_responses = &mut client.partial_responses;

                // Handle writable streams.
                for stream_id in conn.writable() {
                    http_conn.handle_writable(conn, partial_responses, stream_id);
                }

                if http_conn
                    .handle_requests(
                        conn,
                        &mut client.partial_requests,
                        partial_responses,
                        &args.root,
                        &args.index,
                        &mut buf,
                    )
                    .is_err()
                {
                    continue 'read;
                }
            }

            // If we have a siduck connection, handle the quacks.
            if client.siduck_conn.is_some() {
                let conn = &mut client.conn;
                let si_conn = client.siduck_conn.as_mut().unwrap();

                if si_conn.handle_quacks(conn, &mut buf).is_err() {
                    continue 'read;
                }
            }
        }

        // Generate outgoing QUIC packets for all active connections and send
        // them on the UDP socket, until quiche reports that there are no more
        // packets to be sent.
        continue_write = false;
        for client in clients.values_mut() {
            let max_send_burst = client.max_send_burst;
            let mut total_write = 0;
            let mut dst_info = None;
            let mut is_done = false;

            'write: loop {
                while total_write < max_send_burst {
                    let (write, send_info) = match client
                        .conn
                        .send(&mut out[total_write..max_send_burst])
                    {
                        Ok(v) => v,

                        Err(quiche::Error::Done) => {
                            trace!("{} done writing", client.conn.trace_id());
                            is_done = true;
                            break;
                        },

                        Err(e) => {
                            error!(
                                "{} send failed: {:?}",
                                client.conn.trace_id(),
                                e
                            );

                            client.conn.close(false, 0x1, b"fail").ok();
                            break 'write;
                        },
                    };

                    total_write += write;

                    dst_info = Some(send_info);

                    // No GSO, or last packet.
                    if !enable_gso || write < client.max_datagram_size {
                        break;
                    }
                }

                if total_write == 0 || dst_info.is_none() || is_done {
                    break;
                }

                if let Err(e) = send_to(
                    &socket,
                    &out[..total_write],
                    &dst_info.unwrap().to,
                    client.max_datagram_size,
                ) {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        trace!("send() would block");
                        break;
                    }

                    panic!("send_to() failed: {:?}", e);
                }

                trace!(
                    "{} written {} bytes",
                    client.conn.trace_id(),
                    total_write
                );

                // limit write bursting
                client.bytes_sent += total_write;
                total_write = 0;

                if client.bytes_sent >= max_send_burst {
                    trace!(
                        "{} pause writing at {}",
                        client.conn.trace_id(),
                        client.bytes_sent
                    );
                    client.bytes_sent = 0;
                    continue_write = true;
                    break;
                }
            }
        }

        // Garbage collect closed connections.
        clients.retain(|_, ref mut c| {
            trace!("Collecting garbage");

            if c.conn.is_closed() {
                info!(
                    "{} connection collected {:?}",
                    c.conn.trace_id(),
                    c.conn.stats()
                );
            }

            !c.conn.is_closed()
        });
    }
}

/// Generate a stateless retry token.
///
/// The token includes the static string `"quiche"` followed by the IP address
/// of the client and by the original destination connection ID generated by the
/// client.
///
/// Note that this function is only an example and doesn't do any cryptographic
/// authenticate of the token. *It should not be used in production system*.
fn mint_token(hdr: &quiche::Header, src: &net::SocketAddr) -> Vec<u8> {
    let mut token = Vec::new();

    token.extend_from_slice(b"quiche");

    let addr = match src.ip() {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    };

    token.extend_from_slice(&addr);
    token.extend_from_slice(&hdr.dcid);

    token
}

/// Validates a stateless retry token.
///
/// This checks that the ticket includes the `"quiche"` static string, and that
/// the client IP address matches the address stored in the ticket.
///
/// Note that this function is only an example and doesn't do any cryptographic
/// authenticate of the token. *It should not be used in production system*.
fn validate_token<'a>(
    src: &net::SocketAddr, token: &'a [u8],
) -> Option<quiche::ConnectionId<'a>> {
    if token.len() < 6 {
        return None;
    }

    if &token[..6] != b"quiche" {
        return None;
    }

    let token = &token[6..];

    let addr = match src.ip() {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    };

    if token.len() < addr.len() || &token[..addr.len()] != addr.as_slice() {
        return None;
    }

    Some(quiche::ConnectionId::from_ref(&token[addr.len()..]))
}

/// For Linux, try to detect GSO is available.
#[cfg(target_os = "linux")]
fn detect_gso(socket: &mio::net::UdpSocket, segment_size: usize) -> bool {
    use nix::sys::socket::setsockopt;
    use nix::sys::socket::sockopt::UdpGsoSegment;
    use std::os::unix::io::AsRawFd;

    setsockopt(socket.as_raw_fd(), UdpGsoSegment, &(segment_size as i32)).is_ok()
}

/// For non-Linux, there is no GSO support.
#[cfg(not(target_os = "linux"))]
fn detect_gso(_socket: &mio::net::UdpSocket, _segment_size: usize) -> bool {
    false
}

/// When GSO enabled, send packets using sendmsg().
#[cfg(target_os = "linux")]
fn send_to(
    socket: &mio::net::UdpSocket, buf: &[u8], target: &net::SocketAddr,
    segment_size: usize,
) -> io::Result<usize> {
    use nix::sys::socket::sendmsg;
    use nix::sys::socket::ControlMessage;
    use nix::sys::socket::InetAddr;
    use nix::sys::socket::MsgFlags;
    use nix::sys::socket::SockAddr;
    use nix::sys::uio::IoVec;
    use std::os::unix::io::AsRawFd;

    let iov = [IoVec::from_slice(buf)];
    let segment_size = segment_size as u16;
    let cmsg = ControlMessage::UdpGsoSegments(&segment_size);
    let dst = SockAddr::new_inet(InetAddr::from_std(target));

    match sendmsg(
        socket.as_raw_fd(),
        &iov,
        &[cmsg],
        MsgFlags::empty(),
        Some(&dst),
    ) {
        Ok(v) => Ok(v),
        Err(e) => {
            let e = match e.as_errno() {
                Some(v) => io::Error::from(v),
                None => io::Error::new(io::ErrorKind::Other, e),
            };
            Err(e)
        },
    }
}

/// When GSO disabled, send a packet using send_to().
#[cfg(not(target_os = "linux"))]
fn send_to(
    socket: &mio::net::UdpSocket, buf: &[u8], target: &net::SocketAddr,
    _segment_size: usize,
) -> io::Result<usize> {
    socket.send_to(buf, target)
}
