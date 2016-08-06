module SSH

    include("constants.jl")

    type Session
        transport::IO
        mac_length::UInt8
        Session(transport) = new(transport, 0)
    end

    immutable PacketBuffer
        buf::IOBuffer
        function PacketBuffer(packet_type)
            buf = IOBuffer()
            write(buf, UInt8(packet_type))
            new(buf)
        end
    end

    Base.write(buf::PacketBuffer, args...) = write(buf.buf, args...)

    function Base.connect(::Type{Session}, transport::IO)
        # Send the indentification string
        write(transport, "SSH-2.0-SSH.jlv0.1 Do not use in production systems\r\n")
        ident = readuntil(transport, "\r\n")[1:end-2]
        # Some servers may announce dual-version support by sending SSH-1.99-. They
        # are not supported.
        startswith(ident, "SSH-2.0-") || error("Invalid identification string")
        Session(transport)
    end

    function read_packet(session)
        packet_length = bswap(read(session.transport, UInt32))
        padding_length = read(session.transport, UInt8)
        payload = read(session.transport, packet_length - padding_length - sizeof(UInt8))
        read(session.transport, padding_length)
        mac = read(session.transport, session.mac_length)
        IOBuffer(payload)
    end

    function Base.write(session::Session, buf::PacketBuffer)
        payload = takebuf_array(copy(buf.buf))
        block_size = 8
        packet_length = sizeof(payload) + sizeof(UInt8)
        padding_size = mod(block_size-mod(packet_length+sizeof(UInt32), block_size), block_size)
        if padding_size < 4
            padding_size += block_size
        end
        packet_length += padding_size
        # Blackhole writes if the connection is closed, but still allow reads
        # to be processed
        if isopen(session.transport)
            write(session.transport, bswap(UInt32(packet_length)))
            write(session.transport, UInt8(padding_size))
            write(session.transport, payload)
            write(session.transport, rand(UInt8, padding_size))
        end
        # mac
    end

    function require_packet(session, kind)
        packet = read_packet(session)
        @assert read(packet, UInt8) == kind
        packet
    end

    const kex_algorithms = ["diffie-hellman-group14-sha1"]
    const server_host_key_algorithms = ["ssh-dss","ssh-rsa"]
    const encryption_algorithms = ["aes128-ctr","aes192-ctr","aes256-ctr","aes128-gcm@openssh.com","aes256-gcm@openssh.com"]
    const mac_algorithms = ["mac-64-etm@openssh.com","umac-128-etm@openssh.com","hmac-sha2-256-etm@openssh.com","hmac-sha2-512-etm@openssh.com",
        "hmac-sha1-etm@openssh.com","umac-64@openssh.com","umac-128@openssh.com","hmac-sha2-256","hmac-sha2-512","hmac-sha"]
    const compression_algorithms = ["zlib","none"]

    function write_name_list(io, list)
        nl = join(list, ",")
        write(io, bswap(UInt32(sizeof(nl))))
        write(io, nl)
    end

    function send_kexinit!(session)
        packet = PacketBuffer(SSH_MSG_KEXINIT)
        write(packet, rand(UInt8, 16))
        write_name_list(packet, kex_algorithms)
        write_name_list(packet, server_host_key_algorithms)
        write_name_list(packet, encryption_algorithms)
        write_name_list(packet, encryption_algorithms)
        write_name_list(packet, mac_algorithms)
        write_name_list(packet, mac_algorithms)
        write_name_list(packet, compression_algorithms)
        write_name_list(packet, compression_algorithms)
        write_name_list(packet, [])
        write_name_list(packet, [])
        write(packet, UInt8(0)) # first_kex_packet_follows
        write(packet, UInt32(0))

        write(session, packet)
    end

    function negotiate_algorithm(packet, client_list; allow_none = false)
        list = read_name_list(packet)
        idx = findfirst(alg->alg in list, client_list)
        !allow_none && idx == 0 && error("Could not negotiate")
        idx == 0 ? "" : client_list[idx]
    end

    function read_name_list(packet)
        nbytes = bswap(read(packet, UInt32))
        data = read(packet,nbytes)
        Set(split(String(data),','))
    end
    function negotiate_algorithms!(session)
        send_kexinit!(session)
        packet = require_packet(session, SSH_MSG_KEXINIT)
        skip(packet, 16) # Cookie
        remote_kex_algorithms = read_name_list(packet)
        remote_host_key_algorithms = read_name_list(packet)
        kex_algorithm = findfirst(alg->alg in remote_kex_algorithms, kex_algorithms)
        cs_crypt_algorithm = negotiate_algorithm(packet, encryption_algorithms)
        sc_crypt_algorithm = negotiate_algorithm(packet, encryption_algorithms)
        cs_mac_algorithm = negotiate_algorithm(packet, mac_algorithms)
        sc_mac_algorithm = negotiate_algorithm(packet, mac_algorithms)
        cs_comp_algorithm = negotiate_algorithm(packet, compression_algorithms)
        sc_comp_algorithm = negotiate_algorithm(packet, compression_algorithms)
        cs_lang_algorithm = negotiate_algorithm(packet, []; allow_none = true)
        sc_lang_algorithm = negotiate_algorithm(packet, []; allow_none = true)
        first_kex_packet_follows = read(packet, UInt8)
        reserved = read(packet, UInt32)
        @assert first_kex_packet_follows == false && reserved == 0
    end

    function write_mpint(packet, mpint::BigInt)
        size = ndigits(mpint, 2)
        nbytes = div(size+8-1,8)
        data = Array(UInt8, nbytes)
        count = Ref{Csize_t}(0)
        ccall((:__gmpz_export,:libgmp), Ptr{Void},
                (Ptr{Void}, Ptr{Csize_t}, Cint, Csize_t, Cint, Csize_t, Ptr{BigInt}),
                data, count, 1, 1, 1, 0, &mpint)
        @assert count[] == nbytes
        # Need extra padding
        need_padding = false
        if size % 8 == 0
            nbytes += 1
            need_padding = true
        end
        write(packet, bswap(UInt32(nbytes)))
        if need_padding
            write(packet, UInt8(0))
        end
        write(packet, data)
    end

    function import_bigint{T}(data::Vector{T})
        b = BigInt()
        ccall((:__gmpz_import,:libgmp), Ptr{Void},
            (Ptr{BigInt}, Csize_t, Cint, Csize_t, Cint, Csize_t, Ptr{Void}),
            &b, length(data), 1, sizeof(data[]), 1, 0, data)
        b
    end

    function read_mpint(packet)
        data = read(packet, bswap(read(packet, UInt32)))
        import_bigint(data)
    end

    immutable DHGroup
        g::BigInt
        p::BigInt
        x_max::BigInt
    end
    DHGroup(g::BigInt,data::Vector) = DHGroup(g, import_bigint(data), BigInt(2)^1024)

    # RFC 3526 Group 14
    const group14 = DHGroup(BigInt(2),[
        0xFFFFFFFF, 0xFFFFFFFF, 0xC90FDAA2, 0x2168C234, 0xC4C6628B, 0x80DC1CD1,
        0x29024E08, 0x8A67CC74, 0x020BBEA6, 0x3B139B22, 0x514A0879, 0x8E3404DD,
        0xEF9519B3, 0xCD3A431B, 0x302B0A6D, 0xF25F1437, 0x4FE1356D, 0x6D51C245,
        0xE485B576, 0x625E7EC6, 0xF44C42E9, 0xA637ED6B, 0x0BFF5CB6, 0xF406B7ED,
        0xEE386BFB, 0x5A899FA5, 0xAE9F2411, 0x7C4B1FE6, 0x49286651, 0xECE45B3D,
        0xC2007CB8, 0xA163BF05, 0x98DA4836, 0x1C55D39A, 0x69163FA8, 0xFD24CF5F,
        0x83655D23, 0xDCA3AD96, 0x1C62F356, 0x208552BB, 0x9ED52907, 0x7096966D,
        0x670C354E, 0x4ABC9804, 0xF1746C08, 0xCA18217C, 0x32905E46, 0x2E36CE3B,
        0xE39E772C, 0x180E8603, 0x9B2783A2, 0xEC07A28F, 0xB5C55DF0, 0x6F4C52C9,
        0xDE2BCBF6, 0x95581718, 0x3995497C, 0xEA956AE5, 0x15D22618, 0x98FA0510,
        0x15728E5A, 0x8AACAA68, 0xFFFFFFFF, 0xFFFFFFFF ])

    function client_dh_kex!(session)
        packet = PacketBuffer(SSH_MSG_KEXDH_INIT)
        group = group14
        # Perform Diffie-Hellman key exchange
        x = rand(1:group.x_max)
        e = powermod(group.g, x, group.p)
        write_mpint(packet, e)
        write(session, packet)
        response = require_packet(session, SSH_MSG_KEXDH_REPLY)
        cert = read(response, bswap(read(response, UInt32)))
        f = read_mpint(response)
        signature = read(response, bswap(read(response, UInt32)))
        # Validate signature here, I guess
        write(session, PacketBuffer(SSH_MSG_NEWKEYS))
    end

end # module
