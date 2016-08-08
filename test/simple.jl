reload("SSH")
sock = connect("localhost", 10000)
session = SSH.connect(SSH.Session, sock)
SSH.negotiate_algorithms!(session)
SSH.client_dh_kex!(session)
SSH.enter_userauth!(session)
SSH.clientauth_list(session, "kfischer", "ssh-connection")
@assert SSH.clientauth_pubkey(session, "kfischer",
    joinpath(ENV["HOME"],".ssh","id_rsa.pub"),
    joinpath(ENV["HOME"],".ssh","id_rsa"))
