module SSH

    const DEBUG_KEX = false
    using DataStructures
    using Sockets, Base64
    using Random
    using MbedTLS

    include("constants.jl")
    include("hexdump.jl")

    mutable struct Session
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

    struct AlgorithmChoices
        kex_algorithm::String
        host_key_algorithm::String
        cs_crypt_algorithm::String
        sc_crypt_algorithm::String
        cs_mac_algorithm::String
        sc_mac_algorithm::String
        cs_comp_algorithm::String
        sc_comp_algorithm::String
        cs_lang_algorithm::String
        sc_lang_algorithm::String
        ext_info_support::Bool
        AlgorithmChoices(;
            kex_algorithm,
            host_key_algorithm,
            cs_crypt_algorithm,
            sc_crypt_algorithm,
            cs_mac_algorithm,
            sc_mac_algorithm,
            cs_comp_algorithm,
            sc_comp_algorithm,
            cs_lang_algorithm,
            sc_lang_algorithm,
            ext_info_support) = new(
                kex_algorithm,
                host_key_algorithm,
                cs_crypt_algorithm,
                sc_crypt_algorithm,
                cs_mac_algorithm,
                sc_mac_algorithm,
                cs_comp_algorithm,
                sc_comp_algorithm,
                cs_lang_algorithm,
                sc_lang_algorithm,
                ext_info_support)
    end

    mutable struct Channel <: IO
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

    struct PacketBuffer
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
    function Sockets.connect(::Type{Session}, transport::IO; client = true)
        # Send the indentification string
        write(transport, our_ident, "\r\n")
        ident = readuntil(transport, "\r\n")
        # Some servers may announce dual-version support by sending SSH-1.99-. They
        # are not supported.
        startswith(ident, "SSH-2.0-") || error("Invalid identification string `$ident`")
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
        buf = IOBuffer(session.decrypt!(encrypted_begin); read=true, write=true)
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
        payload = take!(copy(buf.buf))
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
            unencrypted_data = take!(buf)
            hmac = session.hmac(unencrypted_data, session.sequence_number)
            encrypted = session.encrypt!(unencrypted_data)
            sendbuf = IOBuffer()
            write(sendbuf, encrypted); write(sendbuf, hmac)
            # Make sure this is task-atomic
            session.sequence_number += 1
            write(session.transport, take!(sendbuf))
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

    const KEX_DH14_SHA1 = "diffie-hellman-group14-sha1"
    const KEX_DH14_SHA256 = "diffie-hellman-group14-sha256"

    const HK_RSA_SHA1 = "ssh-rsa"
    const HK_RSA_SHA256 = "rsa-sha2-256"

    const kex_algorithms = [KEX_DH14_SHA1, KEX_DH14_SHA256]
    const server_host_key_algorithms = [HK_RSA_SHA1, HK_RSA_SHA256]
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
        local_kex_algorithms = copy(kex_algorithms)
        if session.is_client
            push!(local_kex_algorithms, "ext-info-c")
        else
            push!(local_kex_algorithms, "ext-info-s")
        end
        write_name_list(packet, local_kex_algorithms)
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
            session.I_C = take!(copy(packet))
        else
            session.I_S = take!(copy(packet))
        end
        write(session, packet)
    end

    function negotiate_algorithm!(packet, our_list; allow_none = false)
        remote_list = read_name_list(packet)
        return _negotiate_algorithm(remote_list, our_list; allow_none)
    end

    function _negotiate_algorithm(remote_list, our_list; allow_none = false)
        idx = findfirst(alg->alg in remote_list, our_list)
        if idx === nothing
            allow_none || error("Could not negotiate")
            return ""
        end
        return our_list[idx]
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
            session.I_S = take!(copy(packet))
        else
            session.I_C = take!(copy(packet))
        end
        skip(packet, 16) # Cookie
        remote_kex_list = read_name_list(packet)
        kex_algorithm = _negotiate_algorithm(remote_kex_list, kex_algorithms)
        ext_info_support = (session.is_client ? "ext-info-s" : "ext-info-c") in remote_kex_list
        host_key_algorithm = negotiate_algorithm!(packet, server_host_key_algorithms)
        cs_crypt_algorithm = negotiate_algorithm!(packet, encryption_algorithms)
        sc_crypt_algorithm = negotiate_algorithm!(packet, encryption_algorithms)
        cs_mac_algorithm = negotiate_algorithm!(packet, mac_algorithms)
        sc_mac_algorithm = negotiate_algorithm!(packet, mac_algorithms)
        cs_comp_algorithm = negotiate_algorithm!(packet, compression_algorithms)
        sc_comp_algorithm = negotiate_algorithm!(packet, compression_algorithms)
        cs_lang_algorithm = negotiate_algorithm!(packet, []; allow_none = true)
        sc_lang_algorithm = negotiate_algorithm!(packet, []; allow_none = true)
        first_kex_packet_follows = read(packet, UInt8)
        reserved = read(packet, UInt32)
        @assert first_kex_packet_follows == false && reserved == 0
        AlgorithmChoices(; kex_algorithm, host_key_algorithm, cs_crypt_algorithm, sc_crypt_algorithm,
            cs_mac_algorithm, sc_mac_algorithm, cs_comp_algorithm,
            sc_comp_algorithm, cs_lang_algorithm, sc_lang_algorithm,
            ext_info_support)
    end

    function write_mpint(packet, mpint::BigInt)
        size = ndigits(mpint; base=2)
        nbytes = div(size+8-1,8)
        data = Vector{UInt8}(undef, nbytes)
        Base.GMP.MPZ.export!(data, mpint; order=1, endian=1)
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

    function write_mpint(packet, mpint::MbedTLS.MPI)
        sz = MbedTLS.mpi_size(mpint)
        need_padding = false
        if sz % 8 == 0
            sz += 1
            need_padding = true
        end
        write_string_length(packet, sz)
        need_padding && write(packet, UInt8(0))
        MbedTLS.mpi_export!(packet, mpint)
    end

    function import_bigint(data::Vector)
        b = BigInt()
        ccall((:__gmpz_import,Base.GMP.MPZ.libgmp), Ptr{Cvoid},
            (Base.GMP.MPZ.mpz_t, Csize_t, Cint, Csize_t, Cint, Csize_t, Ptr{Cvoid}),
            b, length(data), 1, sizeof(eltype(data)), 1, 0, data)
        b
    end

    read_string(packet) = read(packet, bswap(read(packet, UInt32)))
    write_string_length(packet, len::Integer) = write(packet, bswap(UInt32(len)))
    write_string(packet, data) = (write_string_length(packet, sizeof(data)); write(packet, data))
    function read_mpint(packet)
        data = read_string(packet)
        import_bigint(data)
    end

    struct DHGroup
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

    function update_string!(hasher, string)
        update!(hasher, reinterpret(UInt8,[bswap(UInt32(sizeof(string)))]))
        update!(hasher, string)
    end

    function mpint_arr(mpint)
        buf = IOBuffer()
        write_mpint(buf, mpint)
        take!(buf)
    end

    function write_kex_data(out, session, K_S, e_data, f_data, K)
        write_string(out, session.V_C)
        write_string(out, session.V_S)
        write_string(out, session.I_C)
        write_string(out, session.I_S)
        write_string(out, K_S)
        write_string(out, e_data)
        write_string(out, f_data)
        write_mpint(out, K)
    end

    function compute_kex_hash(session, K_S, e_data, f_data, K; md_alg=MD_SHA1)
        hasher=MbedTLS.MD(md_alg)
        write_kex_data(hasher, session, K_S, e_data, f_data, K)
        if DEBUG_KEX
            buf = IOBuffer()
            write_kex_data(buf, session, K_S, e_data, f_data, K)
            hexdump!(stdout, take!(buf))
        end
        MbedTLS.finish!(hasher)
    end

    function setup_crypt!(session, K, H; md_alg=MD_SHA1, hmac_alg=MD_SHA1)
        K_data = mpint_arr(K)
        # Key derivation (rfc4253 - 7.2)
        # HASH(K || H || X || session_id)
        function derive_key(X)
            hasher=MbedTLS.MD(md_alg)
            write(hasher, K_data)
            write(hasher, H)
            write(hasher, UInt8[X])
            write(hasher, session.session_id)
            MbedTLS.finish!(hasher)
        end
        cipher_type = MbedTLS.CipherInfo(MbedTLS.CIPHER_AES_128_CTR)
        block_size = 16
        cs_IV = derive_key('A')[1:block_size]
        sc_IV = derive_key('B')[1:block_size]
        cs_enc = derive_key('C')[1:block_size]
        sc_enc = derive_key('D')[1:block_size]
        cs_int = derive_key('E')[1:20]
        sc_int = derive_key('F')[1:20]

        if DEBUG_KEX
            println("Key A:"); hexdump!(stdout, cs_IV)
            println("Key B:"); hexdump!(stdout, sc_IV)
            println("Key C:"); hexdump!(stdout, cs_enc)
            println("Key D:"); hexdump!(stdout, sc_enc)
            println("Key E:"); hexdump!(stdout, cs_int)
            println("Key F:"); hexdump!(stdout, sc_int)
        end

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
            hmac = Vector{UInt8}(undef, 20)
            hmacx = MbedTLS.MD(hmac_alg, session.is_client ? cs_int : sc_int)
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

    function derive_pubkey(pk, algname)
        rsa = MbedTLS.RSA(pk)
        MbedTLS.complete!(rsa)
        (; N, E) = rsa
        KSbuf = IOBuffer()
        write_string(KSbuf, algname)
        write_mpint(KSbuf, E)
        write_mpint(KSbuf, N)
        K_S = take!(KSbuf)
        return K_S
    end

    function server_dh_kex!(session::Session, algorithms::AlgorithmChoices, hostkey_priv)
        group = group14

        # Parse private key
        pk = MbedTLS.parse_keyfile(hostkey_priv)

        # Get client's public value
        packet = require_packet(session, SSH_MSG_KEXDH_INIT)
        e_data = read_string(packet)
        e = import_bigint(e_data)

        # Prepare response
        packet = PacketBuffer(SSH_MSG_KEXDH_REPLY)

        # Derive K_S from private key data
        K_S = derive_pubkey(pk, "ssh-rsa")
        write_string(packet, K_S)

        # Compute y, f
        y = rand(0:group.x_max)
        f = powermod(group.g, y, group.p)
        f_data = mpint_arr(f)

        write(packet, f_data)

        # Determine MD algorithm from negotiated kex
        kex_md_alg = algorithms.kex_algorithm == KEX_DH14_SHA1 ? MD_SHA1 :
                     algorithms.kex_algorithm == KEX_DH14_SHA256 ? MD_SHA256 :
                     error("Unknown MD for kex algorithm")

        # Compute K and H
        K = powermod(e, y, group.p)
        session.session_id = H = compute_kex_hash(session, K_S, e_data, f_data[5:end], K; md_alg=kex_md_alg)

        # Sign H
        hk_md_alg = algorithms.host_key_algorithm == HK_RSA_SHA1 ? MD_SHA1 :
                    algorithms.host_key_algorithm == HK_RSA_SHA256 ? MD_SHA256 :
                    error("Unknown MD for hostkey algorithm")
        write_string(packet, generate_signature(algorithms.host_key_algorithm, pk, H; md_alg=hk_md_alg))

        # Send back the packet
        write(session, packet)

        # Set up crypto
        setup_crypt!(session, K, H; md_alg=kex_md_alg)
    end

    function send_server_sig_info!(session)
        packet = PacketBuffer(SSH_MSG_EXT_INFO)
        write(packet, bswap(UInt32(1)))
        write_string(packet, "server-sig-algs")
        write_name_list(packet, server_host_key_algorithms)
        write(session, packet)
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

    function wait_for_userauth(session; allow_none=false, publickey = nothing, keyboard_interactive=nothing, success_message = true)
        @assert String(read_string(require_packet(session, SSH_MSG_SERVICE_REQUEST))) == "ssh-userauth"
        packet = PacketBuffer(SSH_MSG_SERVICE_ACCEPT)
        write_string(packet, "ssh-userauth"); write(session, packet)
        local username

        while true
            packet = require_packet(session, SSH_MSG_USERAUTH_REQUEST)
            username = String(read_string(packet))
            servicename = String(read_string(packet))
            methodname = String(read_string(packet))
            @assert servicename == "ssh-connection"
            if methodname == "none"
                if allow_none
                    success_message && write(session, PacketBuffer(SSH_MSG_USERAUTH_SUCCESS))
                    break
                end
            elseif methodname == "publickey"
                has_sig = read(packet, UInt8) != 0
                algorithm = read_string(packet)
                blob = read_string(packet)
                if publickey !== nothing && publickey(username, algorithm, blob)
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
                        @assert String(algname) == "ssh-rsa"
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
                        algorithm = String(algorithm)
                        sig_md_alg = algorithm == HK_RSA_SHA1 ? MD_SHA1 :
                                     algorithm == HK_RSA_SHA256 ? MD_SHA256 :
                                     error("Unknown signature algorithm")
                        # Verify signature (throws on failure)
                        MbedTLS.verify(pubkey, sig_md_alg,
                            MbedTLS.digest(sig_md_alg, take!(sigbuf)),
                            sigblob)
                        # Indicate authentication success
                        success_message && write(session, PacketBuffer(SSH_MSG_USERAUTH_SUCCESS))
                        break
                    end
                    # Fall through to USERAUTH_FAILURE
                end
                # Fall through to USERAUTH_FAILURE
            elseif methodname == "keyboard-interactive"
                language_tag = read_string(packet)
                submethods = read_string(packet)
                if keyboard_interactive(session, submethods)
                    success_message && write(session, PacketBuffer(SSH_MSG_USERAUTH_SUCCESS))
                    break
                end
                # Fall through to USERAUTH_FAILURE
            else
                error("Unsupported Method `$methodname`")
            end
            userauth_failure(session, publickey=publickey,keyboard_interactive=keyboard_interactive)
        end

        return username
    end
    function userauth_failure(session;publickey=nothing,keyboard_interactive=nothing,partial_success=false)
        packet = PacketBuffer(SSH_MSG_USERAUTH_FAILURE)
        avilable_methods = []
        publickey !== nothing && push!(avilable_methods, "publickey")
        keyboard_interactive !== nothing && push!(avilable_methods, "keyboard-interactive")
        write_name_list(packet, avilable_methods); write(packet, UInt8(partial_success))
        write(session, packet)
    end
    function userauth_partial_success(session;kwargs...)
        userauth_failure(session;kwargs...,partial_success=true)
        wait_for_userauth(session; kwargs..., success_message = false)
        return true
    end


    function keyboard_interactive_prompt(session, name, instruction, prompts = [], echo = true)
        packet = PacketBuffer(SSH_MSG_USERAUTH_INFO_REQUEST)
        write_string(packet, name)
        write_string(packet, instruction)
        write_string(packet, "")
        nprompts = isa(prompts, Array) ? length(prompts) : 1
        write(packet, bswap(Cint(nprompts)))
        isa(prompts, Array) && !isa(echo, Array) && (echo = fill!(Vector{Bool}(length(prompts)),echo))
        for (prompt, do_echo) in (isa(prompts, Array) ? zip(prompts,echo) : zip((prompts,),(echo,)))
            write_string(packet, prompt)
            write(packet, UInt8(do_echo))
        end
        write(session, packet)
        reply = require_packet(session, SSH_MSG_USERAUTH_INFO_RESPONSE)
        nreplys = bswap(read(reply, Cint))
        if nreplys != nprompts
            error("Reply number mismatch")
        end
        replys = map(1:nreplys) do _
            read_string(reply)
        end
        return !isa(prompts, Array) ? replys[] : replys
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

    function generate_signature(sig_algorithm, pk, data; md_alg=MD_SHA1)
        sig = Vector{UInt8}(undef, 1024)
        rng = Random.MersenneTwister()
        len = MbedTLS.sign!(pk, md_alg, MbedTLS.digest(md_alg, data), sig, rng)
        sig_buf = IOBuffer()
        write_string(sig_buf, sig_algorithm)
        write_string(sig_buf, sig[1:len])
        take!(sig_buf)
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
        pk = MbedTLS.parse_keyfile(privkey)
        write_string(packet, generate_signature("ssh-rsa", pk, take!(buf)))

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

    function Base.write(chan::Channel, data::Vector{UInt8})
        _write(chan, data)
    end

    function Base.write(chan::Channel, data::String)
        _write(chan, data)
    end

    function _write(chan::Channel, data)
        packet = PacketBuffer(SSH_MSG_CHANNEL_DATA)
        write(packet, bswap(chan.remote_number))
        write_string(packet, data)
        write(chan.session, packet)
    end

    function Base.close(chan::Channel)
        chan.isopen = false
        packet = PacketBuffer(SSH_MSG_CHANNEL_CLOSE)
        write(packet, bswap(chan.remote_number))
        write(chan.session, packet)
    end

    function send_exit_status!(chan::Channel, status::UInt32)
        packet = PacketBuffer(SSH_MSG_CHANNEL_REQUEST)
        write(packet, bswap(chan.remote_number))
        write_string(packet, "exit-status")
        write(packet, 0x00)
        write(packet, bswap(status))
        write(chan.session, packet)
    end

    Base.bytesavailable(chan::Channel) = bytesavailable(chan.input_buffer)

    function Base.readavailable(chan::Channel)
        while bytesavailable(chan) == 0
            wait(chan.data_available)
        end
        readavailable(chan.input_buffer)
    end

    function Base.read(chan::Channel, ::Type{UInt8})
        while bytesavailable(chan) == 0
            wait(chan.data_available)
        end
        read(chan.input_buffer, UInt8)
    end

    function Base.check_open(chan::Channel)
        if !isopen(chan)
            throw(IOError("Channel is closed", 0))
        end
    end

    on_channel_request(f, chan) = chan.on_channel_request = f

    function allocate_channel_no(session)
        idx = DataStructures.nextnot(session.allocated_channels, 1)[2]
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
                push!(session.allocated_channels, local_no)
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
            elseif kind == SSH_MSG_CHANNEL_CLOSE
                channel_no = bswap(read(packet, UInt32))
                chan = session.channels[channel_no]
                if chan.isopen
                    close(chan)
                end
                session.channels[channel_no] = nothing
                pop!(session.allocated_channels, channel_no)
            elseif kind == SSH_MSG_DISCONNECT
                close(session.transport)
                return true
            else
                packet = PacketBuffer(SSH_MSG_UNIMPLEMENTED)
                write(packet, bswap(UInt32(session.recv_sequence_number)))
                write(session, packet)
            end
        end
    end

    function accept_session(sock, hostkey)
        client = accept(sock)
        session = connect(SSH.Session, client; client = false)
        algorithms = SSH.negotiate_algorithms!(session)
        SSH.server_dh_kex!(session, algorithms, hostkey)
        if algorithms.ext_info_support
            SSH.send_server_sig_info!(session)
        end
        return session
    end

    struct CheckAuthorizedKeys
        authorized_keys::Union{String, Vector{String}}
    end

    function (this::CheckAuthorizedKeys)(_, _, blob)
        for line in (isa(this.authorized_keys, String) ? eachline(this.authorized_keys) : this.authorized_keys)
            (_, ok_blob) = split(line, ' ')
            if ok_blob == base64encode(blob)
                return true
            end
        end
        return false
    end


    # Encoded terminal modes
    const NCCS = Sys.islinux() ? 32 : 20
    const tcflag_t = Sys.islinux() ? Cuint : Culong
    const speed_t = tcflag_t
    struct termios
        c_iflag::tcflag_t
        c_oflag::tcflag_t
        c_cflag::tcflag_t
        c_lflag::tcflag_t
        @static if Sys.islinux()
            c_line::UInt8
        end
        c_cc::NTuple{NCCS, UInt8}
        c_uispeed::speed_t
        c_ospeed::speed_t
    end

    const maps_idx = Sys.islinux() ? 1 : 2

    op_char_map = Dict(
    #  SSH => (linux, Apple/BSD)
         1 => (  0,  8),  # VINTR
         2 => (  1,  9),  # VQUIT
         3 => (  2,  3),  # VERASE
         4 => (  3,  5),  # VKILL
         5 => (  4,  0),  # VEOF
         6 => ( 11,  1),  # VEOL
         7 => ( 16,  2),  # VEOL2
         8 => (  8, 12),  # VSTART
         9 => (  9, 13),  # VSTOP
        10 => ( 10, 10),  # VSUSP
        11 => ( -1, 11),  # VDUSP
        12 => ( 12,  6),  # VREPRINT
        13 => ( 14,  4),  # VWERASE
        14 => ( 15, 14),  # VLNEXT
        15 => ( -1, -1),  # VFLUSH
        16 => ( -1, -1),  # VSWTCH
        17 => ( -1, 18),  # VSTATUS
        18 => ( -1, 15),  # VDISCARD
    )

    iflag_map = Dict(
    #  SSH => ( Linux   , Apple/BSD )
        30 => (0o0000004, 0x00000004), # IGNPAR
        31 => (0o0000010, 0x00000008), # PARMRK
        32 => (0o0000020, 0x00000010), # INPCK
        33 => (0o0000040, 0x00000020), # ISTRIP
        34 => (0o0000100, 0x00000040), # INLCR
        35 => (0o0000200, 0x00000080), # IGNCR
        36 => (0o0000400, 0x00000100), # ICRNL
        37 => (0o0001000, 0x00000000), # IUCLC
        38 => (0o0002000, 0x00000200), # IXON
        39 => (0o0004000, 0x00000800), # IXANY
        40 => (0o0010000, 0x00000400), # IXOFF
        41 => (0o0020000, 0x00002000), # IMAXBEL
        42 => (0o0040000, 0x00004000), # IUTF8
    )

    lflag_map = Dict(
    #  SSH => ( Linux   , Apple/BSD )
        50 => (0o0000001, 0x00000080), # ISIG
        51 => (0o0000002, 0x00000100), # ICANON
        52 => (0o0000004, 0x00000000), # XCASE
        53 => (0o0000010, 0x00000008), # ECHO
        54 => (0o0000020, 0x00000002), # ECHOE
        55 => (0o0000040, 0x00000004), # ECHOK
        56 => (0o0000100, 0x00000010), # ECHONL
        57 => (0o0000200, 0x80000000), # NOFLSH
        58 => (0o0000400, 0x00400000), # TOSTOP
        59 => (0o0100000, 0x00000400), # IEXTEN
        60 => (0o0001000, 0x00000040), # ECHOCTL
        61 => (0o0004000, 0x00000001), # ECHOKE
        62 => (0o0040000, 0x20000000), # PENDIN
    )

    oflag_map = Dict(
    #  SSH => ( Linux   , Apple/BSD )
        70 => (0o0000001, 0x00000001), # OPOST
        71 => (0o0000002, 0x00000000), # OLCUC
        72 => (0o0000004, 0x00000002), # ONLCR
        73 => (0o0000010, 0x00000010), # OCRNL
        74 => (0o0000020, 0x00000020), # ONOCR
        75 => (0o0000040, 0x00000040), # ONLRET
    )

    cflag_map = Dict(
    #  SSH => ( Linux   , Apple/BSD )
        90 => (0o0000040, 0x00000200), # CS7
        91 => (0o0000060, 0x00000300), # CS8
        92 => (0o0000400, 0x00001000), # PARENB
        93 => (0o0001000, 0x00002000), # PARODD
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
                    op_char_map[opcode][maps_idx] != -1 &&
                        (c_cc[op_char_map[opcode][maps_idx]+1] = operand == 255 ?
                         0 : operand)
                elseif haskey(iflag_map, opcode)
                    iflags |= process_flags(iflags, iflag_map[opcode][maps_idx], operand)
                elseif haskey(lflag_map, opcode)
                    lflags |= process_flags(lflags, lflag_map[opcode][maps_idx], operand)
                elseif haskey(oflag_map, opcode)
                    oflags |= process_flags(oflags, oflag_map[opcode][maps_idx], operand)
                elseif haskey(cflag_map, opcode)
                    cflags |= process_flags(cflags, cflag_map[opcode][maps_idx], operand)
                end
            else
                break
            end
        end
        return termios(iflags, oflags, cflags, lflags,
            (Sys.islinux() ? (0,) : ())..., tuple(c_cc...), 0, 0)
    end

end # module
