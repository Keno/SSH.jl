using SSH, Sockets

@isdefined(sock) && close(sock)
GC.gc() # To run finalizers on socket
port = length(ARGS) >= 1 ? parse(Int, ARGS[1]) : 10000
sock = listen(port)

const O_RDWR = Base.Filesystem.JL_O_RDWR
const O_NOCTTY = Base.Filesystem.JL_O_NOCTTY

function open_fake_pty()
    fdm = ccall(:posix_openpt, Cint, (Cint,), O_RDWR|O_NOCTTY)
    fdm == -1 && error("Failed to open PTY master")
    rc = ccall(:grantpt, Cint, (Cint,), fdm)
    rc != 0 && error("grantpt failed")
    rc = ccall(:unlockpt, Cint, (Cint,), fdm)
    rc != 0 && error("unlockpt")

    fds = ccall(:open, Cint, (Ptr{UInt8}, Cint, UInt32...),
        ccall(:ptsname, Ptr{UInt8}, (Cint,), fdm), O_RDWR|O_NOCTTY)

    # slave
    pts   = RawFD(fds)
    ptm = Base.TTY(RawFD(fdm))
    pts, ptm
end

while true
    client = accept(sock)
    @info "Accepted connection"
    @isdefined(Revise) && Revise.revise()
    invokelatest() do
        @async try
            session = connect(SSH.Session, client; client = false)
            algorithms = SSH.negotiate_algorithms!(session)
            SSH.server_dh_kex!(session, algorithms,
                joinpath(dirname(@__FILE__), "test_only_hostkey"))
            if algorithms.ext_info_support
                SSH.send_server_sig_info!(session)
            end
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
                        elseif kind == "signal"
                            SSH.disconnect(channel.session)
                        elseif kind == "shell"
                            notify(c)
                        elseif kind == "exec"
                            exec_cmd = SSH.read_string(packet)
                            @show String(exec_cmd)
                            notify(c)
                        end
                        want_reply
                    end
                    open(channel)
                    TIOCSCTTY_str = """
                        Libc.systemerror("ioctl",
                        0 != ccall(:ioctl, Cint, (Cint, Cint, Int64), 0,
                        Sys.isbsd() ? 0x20007461 : Sys.islinux() ? 0x540E :
                        error("Fill in TIOCSCTTY for this OS here"), 0))
                    """
                    cmd = """
                        $TIOCSCTTY_str
                        while true
                            print("Req? ")
                            println("Rep: ", readline(stdin))
                        end
                    """
                    @async try
                        wait(c)
                        pts, ptm = open_fake_pty()
                        if @isdefined(encoded_termios)
                            new_termios = Ref{SSH.termios}()
                            systemerror("tcgetattr",
                                -1 == ccall(:tcgetattr, Cint, (Cint, Ptr{Cvoid}), pts, new_termios))
                            new_termios[] = SSH.decode_modes(encoded_termios, new_termios[])
                            systemerror("tcsetattr",
                                -1 == ccall(:tcsetattr, Cint, (Cint, Cint, Ptr{Cvoid}), pts, 0, new_termios))
                        end
                        p = run(detach(`$(Base.julia_cmd()) -e $cmd`), pts, pts, pts; wait=false)
                        @async try
                            while true
                                write(channel, readavailable(ptm))
                            end
                        catch err
                            Base.display_error(err, catch_backtrace())
                        end
                        @async try
                            while true
                                data = readavailable(channel)
                                write(ptm, data)
                            end
                        catch err
                            Base.display_error(err, catch_backtrace())
                        end
                        wait(p)
                        SSH.disconnect(session)
                    catch err
                        Base.display_error(err, catch_backtrace())
                    end
                end
            end
        catch err
            Base.display_error(err, catch_backtrace())
        end
    end
end
