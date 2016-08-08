module SSH

    using DataStructures
    using Nettle
    include("constants.jl")

    const update! = Nettle.update!

    type Session
        transport::IO
        is_client::Bool
        mac_length::UInt8
        sequence_number::UInt32
        recv_sequence_number::UInt32
        block_size::UInt16
        encrypt!::Any
        decrypt!::Any
        hmac::Any
        channels::Vector{Any}
        allocated_channels::DataStructures.IntSet
        V_C::String
        V_S::String
        I_C::Vector{UInt8}
        I_S::Vector{UInt8}
        session_id::Vector{UInt8}
        Session(transport, is_client) = new(transport, is_client, 0, 0, 0, 8, x->x, x->x, (data,seqno)->UInt8[],
            Vector{Any}(), DataStructures.IntSet())
    end

    type Channel
        session::Session
        isopen::Bool
        input_buffer::IOBuffer
        data_available::Condition
        remote_number::UInt32
        local_number::UInt32
        window_size::UInt32
        max_packet_size::UInt32
        on_channel_request::Any
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
    function read_packet(session::Session)
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
        session.recv_sequence_number += 1
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
            sendbuf = IOBuffer()
            write(sendbuf, encrypted); write(sendbuf, hmac)
            # Make sure this is task-atomic
            session.sequence_number += 1
            write(session.transport, takebuf_array(sendbuf))
        end

        # mac
    end

    function require_packet(session::Session)
        local packet
        while true
            packet = read_packet(session)
            if Base.peek(packet) == SSH_MSG_IGNORE
                continue
            end
            break
        end
        packet
    end
    function require_packet(session, kind)
        packet = require_packet(session)
        got_kind = read(packet, UInt8)
        if got_kind != kind
            error("Expected package $kind got $got_kind")
        end
        packet
    end

    const kex_algorithms = ["diffie-hellman-group14-sha1"]
    const server_host_key_algorithms = ["ssh-rsa"]
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

    function mpint_arr(mpint)
        buf = IOBuffer()
        write_mpint(buf, mpint)
        takebuf_array(buf)
    end

    function compute_kex_hash(session, K_S, e_data, f_data, K)
        hasher=Hasher("SHA1")
        update_string!(hasher, session.V_C)
        update_string!(hasher, session.V_S)
        update_string!(hasher, session.I_C)
        update_string!(hasher, session.I_S)
        update_string!(hasher, K_S)
        update_string!(hasher, e_data)
        update_string!(hasher, f_data)
        update!(hasher, mpint_arr(K))
        Nettle.digest!(hasher)
    end

    function setup_crypt!(session, K, H)
        K_data = mpint_arr(K)
        # Key derivation (rfc4253 - 7.2)
        # HASH(K || H || X || session_id)
        function derive_key(X)
            hasher=Hasher("SHA1")
            update!(hasher, K_data)
            update!(hasher, H)
            update!(hasher, UInt8[X])
            update!(hasher, session.session_id)
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

        # If client, Validate signature here, I guess

        # Newkeys barrier
        write(session, PacketBuffer(SSH_MSG_NEWKEYS))
        require_packet(session, SSH_MSG_NEWKEYS)

        # All further traffic will be encrypted
        encryptor = MbedTLS.Cipher(cipher_type)
        MbedTLS.set_key!(encryptor, session.is_client ? cs_enc : sc_enc, MbedTLS.ENCRYPT)
        MbedTLS.set_iv!(encryptor, session.is_client ? cs_IV : sc_IV)
        decryptor = MbedTLS.Cipher(cipher_type)
        MbedTLS.set_key!(decryptor, session.is_client ? sc_enc : cs_enc, MbedTLS.DECRYPT)
        MbedTLS.set_iv!(decryptor, session.is_client ? sc_IV : cs_IV)
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
            hmacx = MbedTLS.MD(MD_SHA1, session.is_client ? cs_int : sc_int)
            write(hmacx, reinterpret(UInt8,[bswap(seqno)]))
            write(hmacx, data)
            MbedTLS.finish!(hmacx, hmac)
            hmac
        end
        session.mac_length = 20
        session.block_size = 16
    end

    function client_dh_kex!(session)
        packet = PacketBuffer(SSH_MSG_KEXDH_INIT)
        group = group14
        # Perform Diffie-Hellman key exchange
        x = rand(1:group.x_max)
        e = powermod(group.g, x, group.p)
        e_data = mpint_arr(e)
        write(packet, e_data)
        write(session, packet)
        response = require_packet(session, SSH_MSG_KEXDH_REPLY)
        K_S = read(response, bswap(read(response, UInt32)))
        f_data = read_string(response)
        f = import_bigint(f_data)
        signature = read(response, bswap(read(response, UInt32)))
        # Compute K
        K = powermod(f, x, group.p)
        K_data = mpint_arr(K)
        # Compute H
        session.session_id = H = compute_kex_hash(session, K_S, e_data[5:end], f_data, K)
        setup_crypt!(session, K, H)
    end

    function server_dh_kex!(session, hostkey_pub, hostkey_priv)
        group = group14
        # Get client's public value
        packet = require_packet(session, SSH_MSG_KEXDH_INIT)
        e_data = read_string(packet)
        e = import_bigint(e_data)

        # Prepare response
        packet = PacketBuffer(SSH_MSG_KEXDH_REPLY)

        # Get K_S from public key
        pubkeydata = read(open(hostkey_pub))
        K_S = base64decode(String(split(String(pubkeydata),' ')[2]))

        write_string(packet, K_S)

        # Compute y, f
        y = rand(0:group.x_max)
        f = powermod(group.g, y, group.p)
        f_data = mpint_arr(f)

        write(packet, f_data)

        # Compute K and H
        K = powermod(e, y, group.p)
        session.session_id = H = compute_kex_hash(session, K_S, e_data, f_data[5:end], K)

        # Sign H
        write_string(packet, generate_signature(pubkeydata, hostkey_priv, H))

        # Send back the packet
        write(session, packet)

        # Set up crypto
        setup_crypt!(session, K, H)
    end

    function disconnect(session)
        packet = PacketBuffer(SSH_MSG_DISCONNECT)
        write(packet, bswap(UInt32(SSH_DISCONNECT_BY_APPLICATION)))
        write_string(packet, "Disconnect requested")
        write_string(packet, "en")
        write(session, packet)
        close(session.transport)
    end

    # Authentication ("ssh-userauth" service) (RFC 4252)
    function enter_userauth!(session)
        packet = PacketBuffer(SSH_MSG_SERVICE_REQUEST)
        write_string(packet, "ssh-userauth")
        write(session, packet)
        @assert read_string(require_packet(session, SSH_MSG_SERVICE_ACCEPT)) == "ssh-userauth"
    end

    function wait_for_userauth(cb::Function, session, methods)
        @assert String(read_string(require_packet(session, SSH_MSG_SERVICE_REQUEST))) == "ssh-userauth"
        packet = PacketBuffer(SSH_MSG_SERVICE_ACCEPT)
        write_string(packet, "ssh-userauth"); write(session, packet)

        while true
            packet = require_packet(session, SSH_MSG_USERAUTH_REQUEST)
            username = String(read_string(packet))
            servicename = String(read_string(packet))
            methodname = String(read_string(packet))
            @assert servicename == "ssh-connection"
            if methodname == "none"
            elseif methodname == "publickey"
                has_sig = read(packet, UInt8) != 0
                algorithm = read_string(packet)
                blob = read_string(packet)
                if cb(username, algorithm, blob)
                    if !has_sig
                        # Inform the client that this public key is acceptable
                        packet = PacketBuffer(SSH_MSG_USERAUTH_PK_OK)
                        write_string(packet, algorithm)
                        write_string(packet, blob)
                        write(session, packet)
                        continue
                    else
                        signature = IOBuffer(read_string(packet))
                        sigmethod = read_string(signature)
                        @assert sigmethod == algorithm
                        sigblob = read_string(signature)
                        # Load the public key
                        blobbuf = IOBuffer(blob)
                        algname = read_string(blobbuf)
                        @assert algname == algorithm
                        e = read_mpint(blobbuf)
                        n = read_mpint(blobbuf)
                        pubkey = MbedTLS.pubkey_from_vals!(MbedTLS.RSA(
                            MbedTLS.MBEDTLS_RSA_PKCS_V15, MD_SHA1), e, n)
                        # Generate the data over which to verify the signature
                        sigbuf = IOBuffer()
                        write_string(sigbuf, session.session_id)
                        write(sigbuf, UInt8(SSH_MSG_USERAUTH_REQUEST))
                        write_string(sigbuf, username); write_string(sigbuf, servicename);
                        write_string(sigbuf, methodname); write(sigbuf, UInt8(1))
                        write_string(sigbuf, algorithm); write_string(sigbuf, blob)
                        # Verify signature (throws on failure)
                        MbedTLS.verify(pubkey, MD_SHA1,
                            MbedTLS.digest(MD_SHA1, takebuf_array(sigbuf)),
                            sigblob)
                        # Indicate authentication success
                        write(session, PacketBuffer(SSH_MSG_USERAUTH_SUCCESS))
                        break
                    end
                    # Fall through to USERAUTH_FAILURE
                end
                # Fall through to USERAUTH_FAILURE
            else
                error("Unsupported Method")
            end
            packet = PacketBuffer(SSH_MSG_USERAUTH_FAILURE)
            write_name_list(packet, methods); write(packet, UInt8(0))
            write(session, packet)
        end
    end

    function clientauth_list(session, username, servicename = "ssh-connection")
        packet = PacketBuffer(SSH_MSG_USERAUTH_REQUEST)
        write_string(packet, username)
        write_string(packet, servicename)
        write_string(packet, "none")
        write(session, packet)
        fp = require_packet(session, SSH_MSG_USERAUTH_FAILURE)
        available_auth = read_name_list(fp)
        @show available_auth
    end

    function generate_signature(pubkeydata, privkey, data)
        pk = MbedTLS.parse_keyfile(privkey)
        sig = Array(UInt8, 1024)
        rng = Base.MersenneTwister()
        len = MbedTLS.sign!(pk, MD_SHA1, MbedTLS.digest(MD_SHA1, data), sig, rng)
        sig_buf = IOBuffer()
        write_string(sig_buf, pubkeydata[1:7])
        write_string(sig_buf, sig[1:len])
        takebuf_array(sig_buf)
    end

    function clientauth_pubkey(session, username, pubkey, privkey, servicename = "ssh-connection")
        packet = PacketBuffer(SSH_MSG_USERAUTH_REQUEST)

        # Open publickey
        pubkeydata = read(open(pubkey))

        # Put together request
        function write_request(io)
            write_string(io, username)
            write_string(io, servicename)
            write_string(io, "publickey")
            write(io, UInt8(1))

            write_string(io, pubkeydata[1:7])
            write_string(io, base64decode(String(split(String(pubkeydata),' ')[2])))
        end
        write_request(packet)

        # Generate rsa signature
        # Step 1: Assemble data to take the signature over
        buf = IOBuffer()
        write_string(buf, session.session_id)
        write(buf, UInt8(SSH_MSG_USERAUTH_REQUEST))
        write_request(buf)

        # Step 2: Open private key and compute signature
        write_string(packet, generate_signature(pubkeydata, privkey, takebuf_array(buf)))

        write(session, packet)
        packet = require_packet(session)
        kind = read(packet, UInt8)
        if kind == SSH_MSG_USERAUTH_SUCCESS
            return true
        elseif kind == SSH_MSG_USERAUTH_FAILURE
            return false
        else
            error(kind)
        end
    end

    # ssh-connection protocol
    Base.isopen(chan::Channel) = chan.isopen
    function Base.open(chan::Channel)
        chan.isopen = true
        packet = PacketBuffer(SSH_MSG_CHANNEL_OPEN_CONFIRMATION)
        write(packet, bswap(chan.remote_number))
        write(packet, bswap(chan.local_number))
        write(packet, bswap(chan.window_size))
        write(packet, bswap(chan.max_packet_size))
        write(chan.session, packet)
    end

    function Base.write(chan::Channel, data)
        packet = PacketBuffer(SSH_MSG_CHANNEL_DATA)
        write(packet, bswap(chan.remote_number))
        write_string(packet, data)
        write(chan.session, packet)
    end

    function Base.readavailable(chan::Channel)
        while nb_available(chan.input_buffer) == 0
            wait(chan.data_available)
        end
        readavailable(chan.input_buffer)
    end

    on_channel_request(f, chan) = chan.on_channel_request = f

    function allocate_channel_no(session)
        idx = DataStructures.nextnot(session.allocated_channels, 0)[2]
        (idx > length(session.channels)) && resize!(session.channels, idx)
        idx
    end

    function perform_ssh_connection(new_chan_cb, session::Session)
        while true
            packet = require_packet(session)
            kind = read(packet, UInt8)
            if kind == SSH_MSG_CHANNEL_OPEN
                chan_kind = read_string(packet)
                remote_no = bswap(read(packet, UInt32))
                initial_window = bswap(read(packet, UInt32))
                max_packet_size = bswap(read(packet, UInt32))
                local_no = allocate_channel_no(session)
                chan = Channel(session, false, PipeBuffer(), Condition(),
                    remote_no, local_no, initial_window, max_packet_size, nothing)
                session.channels[local_no] = chan
                new_chan_cb(String(chan_kind), chan)
                if !isopen(chan)
                    packet = PacketBuffer(SSH_MSG_CHANNEL_OPEN_FAILURE)
                    write(packet, bswap(UInt32(remote_no)))
                    write(packet, bswap(UInt32(SSH_OPEN_UNKNOWN_CHANNEL_TYPE)))
                    write_string(packet, "Unknown channel type")
                    write_string(packet, "en")
                end
            elseif kind == SSH_MSG_CHANNEL_REQUEST
                channel_no = bswap(read(packet, UInt32))
                chan = session.channels[channel_no]
                req_type = String(read_string(packet))
                if chan.on_channel_request !== nothing
                    if chan.on_channel_request(req_type, packet)
                        reply_packet = PacketBuffer(SSH_MSG_CHANNEL_SUCCESS)
                        write(reply_packet, chan.remote_number)
                        write(session, reply_packet)
                    end
                else
                    reply_packet = PacketBuffer(SSH_MSG_CHANNEL_FAILURE)
                    write(reply_packet, chan.remote_number)
                    write(session, reply_packet)
                end
            elseif kind == SSH_MSG_CHANNEL_DATA
                channel_no = bswap(read(packet, UInt32))
                chan = session.channels[channel_no]
                data = read_string(packet)
                write(chan.input_buffer, data)
                notify(chan.data_available)
            else
                @show kind
                packet = PacketBuffer(SSH_MSG_UNIMPLEMENTED)
                write(packet, bswap(UInt32(session.recv_sequence_number)))
                write(session, packet)
            end
        end
    end

    # Encoded terminal modes
    const NCCS = 32
    immutable termios
        c_iflag::Cuint
        c_oflag::Cuint
        c_cflag::Cuint
        c_lflag::Cuint
        c_line::UInt8
        c_cc::NTuple{NCCS, UInt8}
        c_uispeed::Cuint
        c_ospeed::Cuint
    end

    op_char_map = Dict(
         1 =>  0,  # VINTR
         2 =>  1,  # VQUIT
         3 =>  2,  # VERASE
         4 =>  3,  # VKILL
         5 =>  4,  # VEOF
         6 => 11,  # VEOL
         7 => 16,  # VEOL2
         8 =>  8,  # VSTART
         9 =>  9,  # VSTOP
        10 => 10,  # VSUSP
        11 => -1,  # VDUSP
        12 => 12,  # VREPRINT
        13 => 14,  # VWERASE
        14 => 15,  # VLNEXT
        15 => -1,  # VFLUSH
        16 => -1,  # VSWTCH
        17 => -1,  # VSTATUS
        18 => -1,  # VDISCARD
    )

    iflag_map = Dict(
        30 => 0o0000004, # IGNPAR
        31 => 0o0000010, # PARMRK
        32 => 0o0000020, # INPCK
        33 => 0o0000040, # ISTRIP
        34 => 0o0000100, # INLCR
        35 => 0o0000200, # IGNCR
        36 => 0o0000400, # ICRNL
        37 => 0o0001000, # IUCLC
        38 => 0o0002000, # IXON
        39 => 0o0004000, # IXANY
        40 => 0o0010000, # IXOFF
        41 => 0o0020000, # IMAXBEL
        42 => 0o0040000, # IUTF8
    )

    lflag_map = Dict(
        50 => 0o0000001, # ISIG
        51 => 0o0000002, # ICANON
        52 => 0o0000004, # XCASE
        53 => 0o0000010, # ECHO
        54 => 0o0000020, # ECHOE
        55 => 0o0000040, # ECHOK
        56 => 0o0000100, # ECHONL
        57 => 0o0000200, # NOFLSH
        58 => 0o0000400, # TOSTOP
        59 => 0o0100000, # IEXTEN
        60 => 0o0001000, # ECHOCTL
        61 => 0o0004000, # ECHOKE
        62 => 0o0040000, # PENDIN
    )

    oflag_map = Dict(
        70 => 0o0000001, # OPOST
        71 => 0o0000002, # OLCUC
        72 => 0o0000004, # ONLCR
        73 => 0o0000010, # OCRNL
        74 => 0o0000020, # ONOCR
        75 => 0o0000040, # ONLRET
    )

    cflag_map = Dict(
        90 => 0o0000040, # CS7
        91 => 0o0000060, # CS8
        92 => 0o0000400, # PARENB
        93 => 0o0001000, # PARODD
    )

    function process_flags(flags, mask, operand)
        if operand != 0
            flags |= mask
        else
            flags &= ~mask
        end
        flags
    end
    function decode_modes(buf, old_termios)
        iflags = UInt32(old_termios.c_iflag)
        lflags = UInt32(old_termios.c_lflag)
        oflags = UInt32(old_termios.c_oflag)
        cflags = UInt32(old_termios.c_cflag)
        c_cc = zeros(UInt8, NCCS)
        for i = 1:NCCS
            c_cc[i] = old_termios.c_cc[i]
        end
        while !eof(buf)
            opcode = read(buf, UInt8)
            if 1 <= opcode <= 159
                operand = bswap(read(buf, UInt32))
                if haskey(op_char_map, opcode)
                    op_char_map[opcode] != -1 &&
                        (c_cc[op_char_map[opcode]+1] = operand == 255 ?
                         0 : operand)
                elseif haskey(iflag_map, opcode)
                    iflags |= process_flags(iflags, iflag_map[opcode], operand)
                elseif haskey(lflag_map, opcode)
                    lflags |= process_flags(lflags, lflag_map[opcode], operand)
                elseif haskey(oflag_map, opcode)
                    oflags |= process_flags(oflags, oflag_map[opcode], operand)
                elseif haskey(cflag_map, opcode)
                    cflags |= process_flags(cflags, cflag_map[opcode], operand)
                end
            else
                break
            end
        end
        return termios(iflags, oflags, cflags, lflags, 0, tuple(c_cc...), 0, 0)
    end

end # module
