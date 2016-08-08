const SSH_MSG_DISCONNECT       = 1
const SSH_MSG_IGNORE           = 2
const SSH_MSG_UNIMPLEMENTED    = 3
const SSH_MSG_DEBUG            = 4
const SSH_MSG_SERVICE_REQUEST  = 5
const SSH_MSG_SERVICE_ACCEPT   = 6
const SSH_MSG_KEXINIT          = 20
const SSH_MSG_NEWKEYS          = 21
const SSH_MSG_KEXDH_INIT       = 30
const SSH_MSG_KEXDH_REPLY      = 31
const SSH_MSG_USERAUTH_REQUEST = 50
const SSH_MSG_USERAUTH_FAILURE = 51
const SSH_MSG_USERAUTH_SUCCESS = 52
const SSH_MSG_USERAUTH_BANNER  = 53

# Messages for Authentication method publickey
const SSH_MSG_USERAUTH_PK_OK   = 60


# Messages for ssh-connection
const SSH_MSG_GLOBAL_REQUEST            =  80
const SSH_MSG_REQUEST_SUCCESS           =  81
const SSH_MSG_REQUEST_FAILURE           =  82
const SSH_MSG_CHANNEL_OPEN              =  90
const SSH_MSG_CHANNEL_OPEN_CONFIRMATION =  91
const SSH_MSG_CHANNEL_OPEN_FAILURE      =  92
const SSH_MSG_CHANNEL_WINDOW_ADJUST     =  93
const SSH_MSG_CHANNEL_DATA              =  94
const SSH_MSG_CHANNEL_EXTENDED_DATA     =  95
const SSH_MSG_CHANNEL_EOF               =  96
const SSH_MSG_CHANNEL_CLOSE             =  97
const SSH_MSG_CHANNEL_REQUEST           =  98
const SSH_MSG_CHANNEL_SUCCESS           =  99
const SSH_MSG_CHANNEL_FAILURE           = 100

const SSH_OPEN_ADMINISTRATIVELY_PROHIBITED = 1
const SSH_OPEN_CONNECT_FAILED              = 2
const SSH_OPEN_UNKNOWN_CHANNEL_TYPE        = 3
const SSH_OPEN_RESOURCE_SHORTAGE           = 4
