reload("SSH")
isdefined(:sock) && close(sock)
gc()
port = length(ARGS) >= 1 ? parse(Int, ARGS[1]) : 10000
sock = listen(port)

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
    slave, master, RawFD(fdm)
end

while true
    client = accept(sock)
    @async begin
        session = connect(SSH.Session, client; client = false)
        SSH.negotiate_algorithms!(session)
        SSH.server_dh_kex!(session,
            joinpath(ENV["HOME"],".ssh","id_rsa.pub"),
            joinpath(ENV["HOME"],".ssh","id_rsa"))
        SSH.wait_for_userauth(session, publickey = function (username, algorithm, blob)
            return true
        end)
        SSH.perform_ssh_connection(session) do kind, channel
            if kind == "session"
                c = Condition()
                local encoded_termios
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
                        encoded_termios = IOBuffer(encoded_modes)
                        notify(c)
                    elseif kind == "signal"
                        SSH.disconnect(channel.session)
                    end
                    want_reply
                end
                open(channel)
                TIOCSCTTY_str = """
                    Libc.systemerror("ioctl",
                    0 != ccall(:ioctl, Cint, (Cint, Cint, Int64), 0,
                    (is_bsd() || is_apple()) ? 0x20007461 : is_linux() ? 0x540E :
                    error("Fill in TIOCSCTTY for this OS here"), 0))
                """
                cmd = """
                    $TIOCSCTTY_str
                    try; run(`lua $(joinpath(ENV["HOME"],"termtris/termtris.lua"))`); end
                """
                @async begin
                    wait(c)
                    slave, master, masterfd = open_fake_pty()
                    new_termios = Ref{SSH.termios}()
                    systemerror("tcgetattr",
                        -1 == ccall(:tcgetattr, Cint, (Cint, Ptr{Void}), slave, new_termios))
                    new_termios[] = SSH.decode_modes(encoded_termios, new_termios[])
                    systemerror("tcsetattr",
                        -1 == ccall(:tcsetattr, Cint, (Cint, Cint, Ptr{Void}), slave, 0, new_termios))
                    p = spawn(detach(`$(Base.julia_cmd()) -e $cmd`), slave, slave, slave)
                    @async while true
                        write(channel, readavailable(master))
                    end
                    @async while true
                        data = readavailable(channel)
                        @show data
                        write(master, data)
                    end
                    wait(p)
                    SSH.disconnect(session)
                end
            end
        end
    end
    println("Done")
end
