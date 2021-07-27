#include "rcon.hh"
#include "rconmsg.hh"
#include "rconexception.hh"
#include <sys/types.h>
#include <cstdlib>
#include <unistd.h>
#include <string>
#include <cstring>
#include <sys/socket.h>
#include <netdb.h>
#include <fstream>
#include <iostream>
#include <sstream>
/* According to POSIX.1-2001 */
#include <sys/select.h>
/* According to earlier standards */
#include <sys/time.h>


namespace Rcon {

    using namespace Protocol;

    void RconApp::printHelp(const std::string & app) const {
        std::cout << std::endl;
        std::cout << "Usage: " << app << " [-iqh] <ip address> <port> <command>" << std::endl;
        std::cout << "   -q     Quiet mode (no extra client side output.)" << std::endl;
        std::cout << "   -i     Interactive mode." << std::endl;
        std::cout << "   -h     Help." << std::endl << std::endl;
    }

    void RconApp::log(const std::stringstream & msg) {
        if (!mOptions["quiet"].boolVal)
        {
            std::cout << msg.str();
        }
    }


    void RconApp::error(const std::stringstream & msg) {
        std::cerr << msg.str();
    }


    void RconApp::getOpts(int argc, char *argv[]) {

        for(;;)
        {
            switch(getopt(argc, argv, "hiq"))
            {
                case 'q':
                    mOptions["quiet"].boolVal = true;
                    continue;

                case 'i':
                    mOptions["interactive"].boolVal = true;
                    continue;

                case '?':
                case 'h':
                default :
                    printHelp(argv[0]);
                    throw AppException("wrong usage");
                    break;

                case -1:
                    break;
            }
            break;
        }
    }


    void RconApp::readConfig(const std::string & cfgFile) {

        std::ifstream file(cfgFile);
        file >> mPassword;
        file.close();
    }


    const std::string & RconApp::getPassword() const {
        return mPassword;
    }


    void RconApp::openConnection(const std::string & ip, const std::string & port) {

        struct addrinfo hints;
        struct addrinfo *result, *rp;
        int s, j;

        memset(&hints, 0, sizeof(struct addrinfo));
        hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_flags = 0;
        hints.ai_protocol = 0;

        s = getaddrinfo(ip.c_str(), port.c_str(), &hints, &result);
        if (s != 0) {
            std::stringstream error;
            error << "getaddrinfo: " << gai_strerror(s) << std::endl;
            throw SocketException(error.str());
        }

        for (rp = result; rp != nullptr; rp = rp->ai_next) {
            mSocketFd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
            if (mSocketFd == -1)
                continue;

            if (connect(mSocketFd, rp->ai_addr, rp->ai_addrlen) != -1)
                break;

            close(mSocketFd);
        }

        if (rp == nullptr) {
            throw SocketException("Could not connect");
        }

        freeaddrinfo(result);
    }


    void RconApp::closeConnection() {
        close(mSocketFd);
    }


    void RconApp::sendPacket(Message *msg) {
        
        uint8_t buf[BUF_SIZE];
        size_t len = msg->encode(buf);
        if (write(mSocketFd, buf, len) != len) {
            throw ProtocolException("partial/failed write");
        }
    }


    Message *RconApp::receivePacket() {

        fd_set rfds;
        struct timeval tv;
        int retval;
        int nread = 0;
        uint8_t buf[BUF_SIZE];

        FD_ZERO(&rfds);
        FD_SET(mSocketFd, &rfds);

        // Wait for message for 0,5 seconds
        tv.tv_sec = 0;
        tv.tv_usec = 500000;

        retval = select(FD_SETSIZE, &rfds, nullptr, nullptr, &tv);
        if (retval == -1) {
            perror("select()");
            throw ProtocolException("select() error");

        } else if (retval) {
            nread = read(mSocketFd, buf, BUF_SIZE);
            if (nread == -1) 
            {
                perror("read");
                close(mSocketFd);
                throw ProtocolException("socket read error");
            }
            return Message::decode(buf, nread);
        }
        else {
            throw ProtocolException("timeout");
        }
    }


    void RconApp::run(int argc, char *argv[]) {


        getOpts(argc, argv);
        bool interactive = mOptions["interactive"].boolVal;

        if (!interactive && argc < 3) {
            printHelp(argv[0]);
            throw AppException("wrong usage"); 
        }

        const std::string ip(argv[optind]);
        const std::string port(argv[optind+1]);

        openConnection(ip, port);

        /**** Read password from cfg ****/
        readConfig(CONFIG_FILE_NAME);

        /**** Login ****/
        Login login(getPassword());
        sendPacket(&login);

        /**** Handle responses ****/
        Message *rcvdMsg = receivePacket();
        if (rcvdMsg->getType() != Message::MSG_LOGIN_RESP) {
            throw ProtocolException("Unexpected message received!");
        }

        LoginResponse *loginResp = static_cast<LoginResponse*>(rcvdMsg);
        if (loginResp->getResult() == 0) {
            throw ProtocolException("Wrong RCON password!");
        }

        delete loginResp;
        loginResp = nullptr;

        if (interactive) {
            std::cout << "Type 'exit' or 'quit' to exit interactive mode." << std::endl;
        }

        do {
            std::string cmdStr;
            if (interactive) {
                std::cout << "> ";
                std::cin >> cmdStr;

            } else {
                cmdStr = argv[optind+2];
            }

            if (cmdStr == "quit" || cmdStr == "exit") {
                break;
            }

            /**** Execute remote command ****/
            Command cmd(cmdStr);
            sendPacket(&cmd);

            /**** Handle responses ****/
            Message::MsgType msgType = Message::MSG_NONE;

            do {
                ServerAck ack;
                rcvdMsg = receivePacket();
                msgType = rcvdMsg->getType();
                CommandResponse *cmdResp = nullptr;
                CommandPartialResponse *cmdPartResp = nullptr;
                ServerMessage *srvMsg = nullptr;
                std::stringstream rconText;
                rconText.str(std::string());
                uint8_t seqNum = 0;

                switch(msgType) {

                    case Message::MSG_CMD_RESP:
                        cmdResp = static_cast<CommandResponse*>(rcvdMsg);
                        rconText << cmdResp->getMessage() << std::endl;
                        log(rconText);
                        delete cmdResp;
                        cmdResp = nullptr;
                        break;

                    case Message::MSG_CMD_PART_RESP:
                        cmdPartResp = static_cast<CommandPartialResponse*>(rcvdMsg);
                        rconText << cmdPartResp->getMessage() << std::endl;
                        log(rconText);
                        delete cmdPartResp;
                        cmdPartResp = nullptr;
                        break;

                    case Message::MSG_SRV_MSG:
                        srvMsg = static_cast<ServerMessage*>(rcvdMsg);
                        seqNum = srvMsg->getSeqNum();
                        rconText << srvMsg->getMessage() << std::endl;
                        log(rconText);
                        delete srvMsg;
                        srvMsg = nullptr;

                        ack.setSeqNum(seqNum);
                        sendPacket(&ack);
                        break;
                }

            } while (msgType == Message::MSG_CMD_PART_RESP ||
                     msgType == Message::MSG_SRV_MSG);
        } while (interactive);

        closeConnection();
    }
}

