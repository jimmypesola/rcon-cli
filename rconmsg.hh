#ifndef __RCONMSG_HH__
#define __RCONMSG_HH__

#include <sys/types.h>
#include <vector>
#include <string>

#define DEBUG_BUFFER_SIZE   1536
#ifdef DEBUG
#define log_debug(buf, len) debug(buf, len)
#else
#define log_debug(buf, len)
#endif

void debug(const uint8_t *buffer, size_t len);

namespace Rcon {

    namespace Protocol {


        /** The abstract message class
          @remarks
             This class' constructors are only called by
             its subclasses, which are more specific message
             types. 
        */
        class Message {

            public:
                /** Possible message types available. */
                enum MsgType {
                    MSG_NONE,
                    MSG_LOGIN,
                    MSG_LOGIN_RESP,
                    MSG_CMD,
                    MSG_CMD_RESP,
                    MSG_CMD_PART_RESP,
                    MSG_SRV_MSG,
                    MSG_SRV_ACK
                };

                /** All packets are at least 8 bytes long */
                static const int INITIAL_PACKET_LENGTH = 8;

                /** The message type identifiers found inside the packets */
                static const uint8_t PKT_LOGIN = 0;
                static const uint8_t PKT_MULTI = 0;
                static const uint8_t PKT_CMD = 1;
                static const uint8_t PKT_SERVER = 2;

                Message() :
                    mType(MSG_NONE)
                {}

                virtual ~Message() {}


                /** A static decoder method
                  @param
                    buffer The byte buffer holding the binary packet data
                  @param
                    length The length of the byte buffer.
                  @return
                    The corresponding decoded message subclass instance.
                */
                static Message *decode(const uint8_t *buffer, size_t length);


                /** Abstract encode method
                  @param
                    buffer The packet byte buffer which to encode the message
                    subclass instance to.
                  @return
                    The size of the message encoded in the packet buffer
                    in bytes.
                */
                virtual size_t encode(uint8_t *buffer) const = 0;

                /** Returns the type of the message */
                MsgType getType() const;

            protected:
                /** Called by subclasses only so the correct message type may be set. */
                explicit Message(MsgType type) :
                    mType(type)
                {}

                /** Encodes the RCon packet header for the packet */
                void encodeHeader(uint8_t *buffer) const;

                /** Calculates the zlib crc32 sum for the encoded packet in the buffer. */
                void calculateCrc(uint8_t *buffer, size_t length) const;

                /** Get next command packet sequence number, unique at least 256 times. */
                static uint8_t getNextSeqNum();

                MsgType mType;
                static uint8_t mNextSeqNum;

            private:
                /** Helper method to extract a printable string from packet data. */
                static std::string extractStr(const uint8_t *buffer, size_t length);
        };


        /** Login message class
          @remarks
            This class represents the BattlEye RCon login packet.
          @param
            password The password which to use in the login message.
        */
        class Login : public Message {
            public:
                Login() :
                    Message(MSG_LOGIN)
                {}

                Login(const Login & login) :
                    Message(MSG_LOGIN),
                    mPassword(login.mPassword)
                {}

                explicit Login(const std::string & password) : 
                    Message(MSG_LOGIN),
                    mPassword(password)
                {}

                virtual ~Login() {}

                /** encode method to serialize the login packet data
                  @param
                    buffer The byte buffer in which to encode the packet.
                  @return
                    The size in bytes of the encoded packet in buffer.
                */
                virtual size_t encode(uint8_t *buffer) const;

                /** Fetches the password from the login message */
                const std::string & getPassword() const;

            protected:
                std::string mPassword;
        };


        /** LoginResponse message class
          @remarks
            This class represents the BattlEye RCon server login response packet.
          @param
            result The result of the server login. 0 if login succeeded, 1 if failed.
        */
        class LoginResponse : public Message {
            public:
                LoginResponse() :
                    Message(MSG_LOGIN_RESP)
                {}

                LoginResponse(const LoginResponse & loginResp) :
                    Message(MSG_LOGIN_RESP),
                    mResult(loginResp.mResult)
                {}

                explicit LoginResponse(uint8_t result) :
                    Message(MSG_LOGIN_RESP),
                    mResult(result)
                {}

                virtual ~LoginResponse() {}

                /** encode method to serialize the login response packet data
                  @param
                    buffer The byte buffer in which to encode the packet.
                  @return
                    The size in bytes of the encoded packet in buffer.
                */
                virtual size_t encode(uint8_t *buffer) const;

                /** Fetches the result from the login response message */
                uint8_t getResult() const;

                /** Sets the result in the login response message */
                void setResult(uint8_t result);

            protected:
                uint8_t mResult;
        };


        /** ServerMessage class
          @remarks
            This class represents the BattlEye RCon server message packet.
          @param
            seqnum The sequence number of the server message packet.
          @param
            msg The text message of the server message packet.
        */
        class ServerMessage : public Message {
            public:
                ServerMessage() : 
                    Message(MSG_SRV_MSG)
                {}

                ServerMessage(const ServerMessage & serverMsg) :
                    Message(MSG_SRV_MSG),
                    mSeqNum(serverMsg.mSeqNum),
                    mMsg(serverMsg.mMsg)
                {}

                explicit ServerMessage(uint8_t seqnum, const std::string & msg) :
                    Message(MSG_SRV_MSG),
                    mSeqNum(seqnum),
                    mMsg(msg)
                {}

                virtual ~ServerMessage() {}

                /** encode method to serialize the server message packet data
                  @param
                    buffer The byte buffer in which to encode the packet.
                  @return
                    The size in bytes of the encoded packet in buffer.
                */
                virtual size_t encode(uint8_t *buffer) const;

                /** Fetches the sequence number from the server message */
                uint8_t getSeqNum() const;

                /** Sets the sequence number in the server message */
                void setSeqNum(uint8_t seqnum);

                /** Fetches the text message from the server message */
                const std::string & getMessage() const;

                /** Sets the text message in the server message */
                void setMessage(const std::string & msg);

            protected:
                /** Called by subclass only so the correct message type may be set. */
                explicit ServerMessage(MsgType msgType) :
                    Message(msgType)
                {}

                /** Called by subclass only so the correct message type may be set. */
                explicit ServerMessage(MsgType msgType, uint8_t seqnum, const std::string & msg) :
                    Message(msgType),
                    mSeqNum(seqnum),
                    mMsg(msg)
                {}

                uint8_t mSeqNum;
                std::string mMsg;
        };


        /** ServerAck class
          @remarks
            This class represents the BattlEye RCon server ACK packet.
          @param
            seqnum The ACKed sequence number of the server ACK packet.
        */
        class ServerAck : public Message {
            public:
                ServerAck() :
                    Message(MSG_SRV_ACK)
                {}

                explicit ServerAck(uint8_t seqnum) :
                    Message(MSG_SRV_ACK),
                    mSeqNum(seqnum)
                {}

                ServerAck(const ServerAck & serverAck) :
                    Message(MSG_SRV_ACK),
                    mSeqNum(serverAck.mSeqNum)
                {}

                virtual ~ServerAck() {}

                /** encode method to serialize the server ACK packet data
                  @param
                    buffer The byte buffer in which to encode the packet.
                  @return
                    The size in bytes of the encoded packet in buffer.
                */
                virtual size_t encode(uint8_t *buffer) const;

                /** Fetches the text message from the server ACK message */
                uint8_t getSeqNum() const;

                /** Sets the text message in the server ACK message */
                void setSeqNum(uint8_t seqnum);

            protected:
                /** Called by subclass only so the correct message type may be set. */
                explicit ServerAck(MsgType msgType) :
                    Message(msgType)
                {}

                /** Called by subclass only so the correct message type may be set. */
                explicit ServerAck(MsgType msgType, uint8_t seqnum) :
                    Message(msgType),
                    mSeqNum(seqnum)
                {}

                uint8_t mSeqNum;
        };


        /** Command message class
          @remarks
            This class represents the BattlEye RCon command message packet.
          @param
            cmd The command to send to the RCon server.
          @param
            seqnum The sequence number of the command to send.
        */
        class Command : public ServerAck {
            public:
                Command() :
                    ServerAck(MSG_CMD, getNextSeqNum())
                {}

                explicit Command(const std::string & cmd) :
                    ServerAck(MSG_CMD, getNextSeqNum()),
                    mCmdStr(cmd)
                {}

                explicit Command(const std::string & cmd, uint8_t seqnum) :
                    ServerAck(MSG_CMD, seqnum),
                    mCmdStr(cmd)
                {}

                Command(const Command & command) :
                    ServerAck(MSG_CMD, getNextSeqNum()),
                    mCmdStr(command.mCmdStr)
                {}

                virtual ~Command() {}

                /** encode method to serialize the RCon command packet data
                  @param
                    buffer The byte buffer in which to encode the packet.
                  @return
                    The size in bytes of the encoded packet in buffer.
                */
                virtual size_t encode(uint8_t *buffer) const;

                /** Fetches the command from the command message */
                const std::string & getCommand() const;

                /** Sets the command in the command message */
                void setCommand(const std::string & cmd);

            protected:
                std::string mCmdStr;
        };

        
        /** Command response message class
          @remarks
            This class represents the BattlEye RCon command response message packet.
            It extends the server message class, and its text message class member
            is used for storing the command result text in the command response message.
          @param
            seqnum The sequence number of the command response message.
          @param
            cmd The command response message from the RCon server.
        */
        class CommandResponse : public ServerMessage {
            public:
                CommandResponse() :
                    ServerMessage(MSG_CMD_RESP)
                {}

                CommandResponse(const CommandResponse & cmdResp) :
                    ServerMessage(cmdResp)
                {}

                explicit CommandResponse(uint8_t seqnum, const std::string & msg) :
                    ServerMessage(MSG_CMD_RESP, seqnum, msg)
                {}

                virtual ~CommandResponse() {}

                /** encode method to serialize the RCon command response packet data
                  @param
                    buffer The byte buffer in which to encode the packet.
                  @return
                    The size in bytes of the encoded packet in buffer.
                */
                virtual size_t encode(uint8_t *buffer) const;
        };


        /** Command partial response message class
          @remarks
            This class represents the BattlEye RCon command partial response message packet.
          @param
            nofParts The number of expected parts of all command partial response messages
            to receive.
          @param
            partIdx The part index number of the current command partial response message.
          @param
            msg The text message of the current command partial response.
        */
        class CommandPartialResponse : public Message {
            public:
                CommandPartialResponse() :
                    Message(MSG_CMD_PART_RESP)
                {}

                explicit CommandPartialResponse(uint8_t nofParts, uint8_t partIdx, const std::string & msg) :
                    Message(MSG_CMD_PART_RESP),
                    mNofParts(nofParts),
                    mPartIdx(partIdx),
                    mMsg(msg)
                {}

                CommandPartialResponse(const CommandPartialResponse & partResp) :
                    Message(MSG_CMD_PART_RESP),
                    mNofParts(partResp.mNofParts),
                    mPartIdx(partResp.mPartIdx),
                    mMsg(partResp.mMsg)
                {}

                virtual ~CommandPartialResponse() {}

                /** encode method to serialize the RCon command partial response packet data
                  @param
                    buffer The byte buffer in which to encode the packet.
                  @return
                    The size in bytes of the encoded packet in buffer.
                */
                virtual size_t encode(uint8_t *buffer) const;

                /** Fetches the number of parts from the command partial response message */
                uint8_t getNofParts() const;

                /** Sets the number of parts in the command partial response message */
                void setNofParts(uint8_t nofParts);

                /** Fetches the current part index from the command partial response message */
                uint8_t getPartIdx() const;

                /** Sets the number of parts in the command partial response message */
                void setPartIdx(uint8_t partIdx);

                /** Fetches the command result text from the command message */
                const std::string & getMessage() const;

                /** Sets the number of parts in the command partial response message */
                void setMessage(const std::string & msg);

            protected:
                uint8_t mNofParts;
                uint8_t mPartIdx;
                std::string mMsg;
        };
    }
}

#endif // __RCONMSG_HH__
