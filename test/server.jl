reload("SSH")
isdefined(:sock) && close(sock)
gc()
sock = listen(22)

function open_fake_pty()
    const O_RDWR = Base.Filesystem.JL_O_RDWR
    const O_NOCTTY = Base.Filesystem.JL_O_NOCTTY

    fdm = ccall(:posix_openpt, Cint, (Cint,), O_RDWR|O_NOCTTY)
    fdm == -1 && error("Failed to open PTY master")
    rc = ccall(:grantpt, Cint, (Cint,), fdm)
    rc != 0 && error("grantpt failed")
    rc = ccall(:unlockpt, Cint, (Cint,), fdm)
    rc != 0 && error("unlockpt")

    fds = ccall(:open, Cint, (Ptr{UInt8}, Cint),
        ccall(:ptsname, Ptr{UInt8}, (Cint,), fdm), O_RDWR|O_NOCTTY)

    # slave
    slave   = RawFD(fds)
    master = Base.TTY(RawFD(fdm); readable = true)
    slave, master
end


while true
    client = accept(sock)
    @async begin
        session = connect(SSH.Session, client; client = false)
        SSH.negotiate_algorithms!(session)
        SSH.server_dh_kex!(session,
            joinpath(ENV["HOME"],".ssh","id_rsa.pub"),
            joinpath(ENV["HOME"],".ssh","id_rsa"))
        SSH.wait_for_userauth(session, ["publickey"]) do username, algorithm, blob
            return true
        end
        SSH.perform_ssh_connection(session) do kind, channel
            if kind == "session"
                c = Condition()
                SSH.on_channel_request(channel) do kind, packet
                    want_reply = read(packet, UInt8) != 0
                    @show kind
                    if kind == "pty-req"
                        TERM_var = SSH.read_string(packet)
                        termwidthchars = bswap(read(packet, UInt32))
                        termheightchars = bswap(read(packet, UInt32))
                        termwidthpixs = bswap(read(packet, UInt32))
                        termheightpixs = bswap(read(packet, UInt32))
                        encoded_modes = SSH.read_string(packet)
                        notify(c)
                    elseif kind == "signal"
                        SSH.disconnect(channel.session)
                    end
                    want_reply
                end
                open(channel)
                @async begin
                    wait(c)
                    slave, master = open_fake_pty()
                    p = spawn(`lua $(joinpath(ENV["HOME"],"termtris/termtris.lua"))`, slave, slave, slave)
                    @async while true
                        write(channel, readavailable(master))
                    end
                    @async while true
                        write(master, readavailable(channel))
                    end
                end
            end
        end
    end
    println("Done")
end
