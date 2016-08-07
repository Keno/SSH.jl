module SSH

    include("constants.jl")

    type Session
        transport::IO
        is_client::Bool
        mac_length::UInt8
        sequence_number::UInt32
        block_size::UInt16
        encrypt!::Any
        decrypt!::Any
        hmac::Any
        V_C::String
        V_S::String
        I_C::Vector{UInt8}
        I_S::Vector{UInt8}
        Session(transport, is_client) = new(transport, is_client, 0, 0, 8, x->x, x->x, (data,seqno)->UInt8[])
    end

    immutable PacketBuffer
        buf::IOBuffer
        function PacketBuffer(packet_type)
            buf = IOBuffer()
            write(buf, UInt8(packet_type))
            new(buf)
        end
    end
    Base.copy(buf::PacketBuffer) = copy(buf.buf)

    Base.write(buf::PacketBuffer, args...) = write(buf.buf, args...)

    our_ident = "SSH-2.0-SSH.jlv0.1 Do not use in production systems"
    function Base.connect(::Type{Session}, transport::IO; client = true)
        # Send the indentification string
        write(transport, our_ident, "\r\n")
        ident = readuntil(transport, "\r\n")[1:end-2]
        # Some servers may announce dual-version support by sending SSH-1.99-. They
        # are not supported.
        startswith(ident, "SSH-2.0-") || error("Invalid identification string")
        sess = Session(transport, client)
        if client
            sess.V_C = our_ident; sess.V_S = ident
        else
            sess.V_C = ident; sess.V_S = our_ident
        end
        sess
    end

    block_size(session) = session.block_size
    function read_packet(session)
        encrypted_begin = read(session.transport, block_size(session))
        buf = IOBuffer(session.decrypt!(encrypted_begin), true, true)
        packet_length = bswap(read(buf, UInt32))
        padding_length = read(buf, UInt8)
        remaining_enc_length = (packet_length + sizeof(UInt32)) - block_size(session)
        remaining = session.decrypt!(read(session.transport, remaining_enc_length))
        pos = position(buf); seekend(buf); write(buf, remaining); seek(buf, pos)
        payload_length = packet_length - padding_length - sizeof(UInt8)
        payload = read(buf, payload_length)
        skip(buf, padding_length)
        # mac is not encrypted
        mac = read(session.transport, session.mac_length)
        # TODO: Verify MAC here
        IOBuffer(payload)
    end

    function Base.write(session::Session, buf::PacketBuffer)
        payload = takebuf_array(copy(buf.buf))
        block_size = session.block_size
        packet_length = sizeof(payload) + sizeof(UInt8)
        padding_size = mod(block_size-mod(packet_length+sizeof(UInt32), block_size), block_size)
        if padding_size < 4
            padding_size += block_size
        end
        packet_length += padding_size
        # Blackhole writes if the connection is closed, but still allow reads
        # to be processed
        if isopen(session.transport)
            buf = IOBuffer()
            write(buf, bswap(UInt32(packet_length)))
            write(buf, UInt8(padding_size))
            write(buf, payload)
            write(buf, rand(UInt8, padding_size))
            unencrypted_data = takebuf_array(buf)
            hmac = session.hmac(unencrypted_data, session.sequence_number)
            encrypted = session.encrypt!(unencrypted_data)
            write(session.transport, encrypted)
            write(session.transport, hmac)
        end
        session.sequence_number += 1
        # mac
    end

    function require_packet(session, kind)
        local packet
        while true
            packet = read_packet(session)
            got_kind = read(packet, UInt8)
            if got_kind == SSH_MSG_IGNORE
                continue
            end
            @assert got_kind == kind
            break
        end
        packet
    end

    const kex_algorithms = ["diffie-hellman-group14-sha1"]
    const server_host_key_algorithms = ["ssh-dss","ssh-rsa"]
    const encryption_algorithms = ["aes128-ctr"]
    const mac_algorithms = ["hmac-sha1"]
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
        if session.is_client
            session.I_C = takebuf_array(copy(packet))
        else
            session.I_S = takebuf_array(copy(packet))
        end
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
        if session.is_client
            session.I_S = takebuf_array(copy(packet))
        else
            session.I_C = takebuf_array(copy(packet))
        end
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

    read_string(packet) = read(packet, bswap(read(packet, UInt32)))
    write_string(packet, data) = (write(packet, bswap(UInt32(sizeof(data)))); write(packet, data))
    function read_mpint(packet)
        data = read_string(packet)
        import_bigint(data)
    end

    immutable DHGroup
        g::BigInt
        p::BigInt
        x_max::BigInt
    end
    DHGroup(g::BigInt,data::Vector) = DHGroup(g, import_bigint(data), BigInt(2)^1024)

    # RFC 3526 Group 14
    const group14 = DHGroup(BigInt(2),map(bswap,[
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
        0x15728E5A, 0x8AACAA68, 0xFFFFFFFF, 0xFFFFFFFF ]))

    using MbedTLS
    using Nettle

    function update_string!(hasher, string)
        update!(hasher, reinterpret(UInt8,[bswap(UInt32(sizeof(string)))]))
        update!(hasher, string)
    end

    function client_dh_kex!(session, hasher=Hasher("SHA1"))
        packet = PacketBuffer(SSH_MSG_KEXDH_INIT)
        group = group14
        # Perform Diffie-Hellman key exchange
        x = rand(1:group.x_max)
        e = powermod(group.g, x, group.p)
        e_buf = IOBuffer()
        write_mpint(e_buf, e)
        e_data = takebuf_array(e_buf)
        write(packet, e_data)
        write(session, packet)
        response = require_packet(session, SSH_MSG_KEXDH_REPLY)
        K_S = read(response, bswap(read(response, UInt32)))
        f_data = read_string(response)
        f = import_bigint(f_data)
        signature = read(response, bswap(read(response, UInt32)))
        # Compute K
        K = powermod(f, x, group.p)
        K_buf = IOBuffer()
        write_mpint(K_buf, K)
        K_data = takebuf_array(K_buf)
        # Compute H
        update_string!(hasher, session.V_C)
        update_string!(hasher, session.V_S)
        update_string!(hasher, session.I_C)
        update_string!(hasher, session.I_S)
        update_string!(hasher, K_S)
        update!(hasher, e_data)
        update_string!(hasher, f_data)
        update!(hasher, K_data)
        H = Nettle.digest!(hasher)
        # Key derivation (rfc4253 - 7.2)
        # HASH(K || H || X || session_id)
        function derive_key(X)
            hasher=Hasher("SHA1")
            update!(hasher, K_data)
            update!(hasher, H)
            update!(hasher, UInt8[X])
            update!(hasher, H)
            Nettle.digest!(hasher)
        end
        cipher_type = MbedTLS.CipherInfo(MbedTLS.CIPHER_AES_128_CTR)
        block_size = 16
        cs_IV = derive_key('A')[1:block_size]
        sc_IV = derive_key('B')[1:block_size]
        cs_enc = derive_key('C')[1:block_size]
        sc_enc = derive_key('D')[1:block_size]
        cs_int = derive_key('E')[1:20]
        sc_int = derive_key('F')[1:20]
        # Validate signature here, I guess
        write(session, PacketBuffer(SSH_MSG_NEWKEYS))
        require_packet(session, SSH_MSG_NEWKEYS)
        encryptor = MbedTLS.Cipher(cipher_type)
        MbedTLS.set_key!(encryptor, cs_enc, MbedTLS.ENCRYPT)
        MbedTLS.set_iv!(encryptor, cs_IV)
        decryptor = MbedTLS.Cipher(cipher_type)
        MbedTLS.set_key!(decryptor, sc_enc, MbedTLS.DECRYPT)
        MbedTLS.set_iv!(decryptor, sc_IV)
        session.encrypt! = function(data)
            MbedTLS.update!(encryptor, data, data)
            @assert MbedTLS.finish!(encryptor, data) == 0
            data
        end
        session.decrypt! = function(data)
            MbedTLS.update!(decryptor, data, data)
            @assert MbedTLS.finish!(decryptor, data) == 0
            data
        end
        session.hmac = function(data, seqno::UInt32)
            hmac = Array(UInt8, 20)
            hmacx = MbedTLS.MD(MD_SHA1, cs_int)
            write(hmacx, reinterpret(UInt8,[bswap(seqno)]))
            write(hmacx, data)
            MbedTLS.finish!(hmacx, hmac)
            hmac
        end
        session.mac_length = 20
        session.block_size = 16
    end

    # Authentication ("ssh-userauth" service) (RFC 4252)
    function enter_userauth!(session)
        packet = PacketBuffer(SSH_MSG_SERVICE_REQUEST)
        write_string(packet, "ssh-userauth")
        write(session, packet)
        read_string(require_packet(session, SSH_MSG_SERVICE_ACCEPT)) == "ssh-userauth"
    end

    function clientauth_list(session, username, servicename)
        packet = PacketBuffer(SSH_MSG_USERAUTH_REQUEST)
        write_string(packet, username)
        write_string(packet, servicename)
        write_string(packet, "none")
        write(session, packet)
        fp = require_packet(session, SSH_MSG_USERAUTH_FAILURE)
        available_auth = read_name_list(fp)
        @show available_auth
    end

    function clientauth_pubkey()

    end

end # module
