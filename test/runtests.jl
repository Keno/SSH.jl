using SSH, Test, Sockets

function hello_world_server(session)
    SSH.perform_ssh_connection(session) do kind, channel
        @test kind == "session"
        c = Condition()
        SSH.on_channel_request(channel) do kind, packet
            want_reply = read(packet, UInt8) != 0
            if kind == "env"
                # Allowed but ignored here
            else
                @test kind == "exec"
                @test String(SSH.read_string(packet)) == "hello"
                notify(c)
            end
            return want_reply
        end
        open(channel)
        @async begin
            wait(c)
            write(channel, "world")
            SSH.send_exit_status!(channel, UInt32(0))
            close(channel)
        end
    end
end

function run_server()
    (port, sock) = listenany(ip"127.0.0.1", 2222)
    task = @async begin
        client = accept(sock)
        session = connect(SSH.Session, client; client = false)
        algorithms = SSH.negotiate_algorithms!(session)
        SSH.server_dh_kex!(session, algorithms,
            joinpath(dirname(@__FILE__), "test_only_hostkey.pub"),
            joinpath(dirname(@__FILE__), "test_only_hostkey"))
        if algorithms.ext_info_support
            SSH.send_server_sig_info!(session)
        end
        SSH.wait_for_userauth(session, allow_none=true)
        hello_world_server(session)
        close(sock)
    end
    (port, task)
end

const clientkey = joinpath(dirname(@__FILE__), "test_only_clientkey")
const known_hosts = joinpath(dirname(@__FILE__), "test_only_known_hosts")

# Test that the standard openssh ssh client can connect to our server
let (port, server_task) = run_server()
    @sync begin
        @async wait(server_task)
        @async begin
            @test read(
                pipeline(`ssh -i $clientkey  -o "UserKnownHostsFile $known_hosts" -p $port localhost hello`,
                    stdin=devnull), String) == "world"
        end
    end
end
