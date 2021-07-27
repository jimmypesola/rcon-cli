#include "rconmsg.hh"
#include "rconexception.hh"
#include <sstream>
#include <iostream>
#include <cstring>
#include <zlib.h>

void debug(const uint8_t *buffer, size_t len) {
    size_t chunk = 32;
    size_t pos = 0;
    char logbuf[DEBUG_BUFFER_SIZE];
    do {
        chunk = (len < chunk) ? len : 32;
        len = len - chunk;
        for (int i=0; i<chunk; ++i) {
            snprintf(logbuf, DEBUG_BUFFER_SIZE, "%02x ", buffer[pos++]);
            std::cerr << logbuf;
        }
        std::cerr << std::endl;
    } while (chunk != len);
}


namespace Rcon {

    namespace Protocol {


        /* Message base class */

        uint8_t Message::mNextSeqNum = 0;

        Message *Message::decode(const uint8_t *buffer, size_t length) {
            log_debug(buffer, length);

            if (length < 8) {
                throw ProtocolException("Empty packet received!");
            }

            if (buffer[0] != 0x42 || buffer[1] != 0x45) {
                throw ProtocolException("Key bytes 'B','E' were not matched in packet header!");
            }

            uint32_t test_crc32 = crc32(0L, buffer + 6, length - 6);
            uint32_t *actual_crc32 = (uint32_t*)(buffer + 2);

            if (test_crc32 != *actual_crc32) {
                std::stringstream error;
                error << "CRC32 check failed against " << std::hex << test_crc32 << ", packet is corrupted!" << std::endl;
                throw ProtocolException(error.str());
            }

            if (buffer[6] != 0xff) {
                std::stringstream error;
                error << "Unexpected byte " << std::hex << buffer[6] << " received at position 6!";
                throw ProtocolException(error.str());
            }

            std::string msg;

            switch(buffer[7]) {

                case PKT_LOGIN:
                    if (length == 9) {
                        return new LoginResponse(buffer[8]);
                    } else { // PKT_MULTI
                        msg = extractStr(buffer + 10, length - 10);
                        return new CommandPartialResponse(buffer[8], buffer[9], msg);
                    }

                case PKT_CMD:
                    msg = extractStr(buffer + 9, length - 9);
                    return new CommandResponse(buffer[8], msg);

                case PKT_SERVER:
                    msg = extractStr(buffer + 9, length - 9);
                    return new ServerMessage(buffer[8], msg);

                default:
                    std::stringstream error;
                    error << "Unknown message type " << std::hex << buffer[7] << " received!";
                    throw ProtocolException(error.str());
            };
            return new LoginResponse(0xff);
        }

        Message::MsgType Message::getType() const {
            return mType;
        }

        void Message::encodeHeader(uint8_t *buffer) const {
            buffer[0] = 0x42;
            buffer[1] = 0x45;
            std::fill(buffer+2, buffer+5, 0x00);
            buffer[6] = 0xff;
        }

        void Message::calculateCrc(uint8_t *buffer, size_t length) const{
            uint32_t *crcPtr = (uint32_t*)(buffer + 2);
            *crcPtr = crc32(0L, buffer + 6, length - 6);
        }

        uint8_t Message::getNextSeqNum() {
            return mNextSeqNum++;
        }

        std::string Message::extractStr(const uint8_t *buffer, size_t length) {
            char *tmp = new char[length+1];
            std::copy(buffer, buffer + length, tmp);
            tmp[length] = '\0';
            const std::string & str = std::string(tmp);
            delete tmp;
            return str;
        }


        /* Login class */

        size_t Login::encode(uint8_t *buffer) const {
            size_t length = 8;
            encodeHeader(buffer);
            buffer[7] = PKT_LOGIN;
            std::copy(mPassword.begin(), mPassword.end(), buffer + length);
            length += mPassword.size();
            calculateCrc(buffer, length);
            log_debug(buffer, length);
            return length;
        }

        const std::string & Login::getPassword() const {
            return const_cast<const std::string &>(mPassword);
        }


        size_t LoginResponse::encode(uint8_t *buffer) const {
            size_t length = 9;
            encodeHeader(buffer);
            buffer[7] = PKT_LOGIN;
            buffer[8] = mResult;
            calculateCrc(buffer, length);
            return length;
        }

        uint8_t LoginResponse::getResult() const {
            return mResult;
        }

        void LoginResponse::setResult(uint8_t result) {
            mResult = result;
        }


        /* ServerMessage class */

        size_t ServerMessage::encode(uint8_t *buffer) const {
            size_t length = 9;
            encodeHeader(buffer);
            buffer[7] = PKT_SERVER;
            buffer[8] = mSeqNum;
            std::copy(mMsg.begin(), mMsg.end(), buffer + length);
            length += mMsg.size();
            calculateCrc(buffer, length);
            return length;
        }

        uint8_t ServerMessage::getSeqNum() const {
            return mSeqNum;
        }

        void ServerMessage::setSeqNum(uint8_t seqnum) {
            mSeqNum = seqnum;
        }

        const std::string & ServerMessage::getMessage() const {
            return mMsg;
        }

        void ServerMessage::setMessage(const std::string & msg) {
            mMsg = msg;
        }


        /* ServerAck class */

        size_t ServerAck::encode(uint8_t *buffer) const {
            size_t length = 9;
            encodeHeader(buffer);
            buffer[7] = PKT_SERVER;
            buffer[8] = mSeqNum;
            calculateCrc(buffer, length);
            return length;
        }

        uint8_t ServerAck::getSeqNum() const {
            return mSeqNum;
        }

        void ServerAck::setSeqNum(uint8_t seqnum) {
            mSeqNum = seqnum;
        }


        /* Command class */

        size_t Command::encode(uint8_t *buffer) const {
            size_t length = 9;
            encodeHeader(buffer);
            buffer[7] = PKT_CMD;
            buffer[8] = mSeqNum;
            std::copy(mCmdStr.begin(), mCmdStr.end(), buffer + length);
            length += mCmdStr.size();
            calculateCrc(buffer, length);
            return length;
        }

        const std::string & Command::getCommand() const {
            return mCmdStr;
        }

        void Command::setCommand(const std::string & cmd) {
            mCmdStr = cmd;
        }


        /* CommandResponse class */

        size_t CommandResponse::encode(uint8_t *buffer) const {
            size_t length = 9;
            encodeHeader(buffer);
            buffer[7] = PKT_CMD;
            buffer[8] = mSeqNum;
            std::copy(mMsg.begin(), mMsg.end(), buffer + length);
            length += mMsg.size();
            calculateCrc(buffer, length);
            return length;
        }


        /* CommandPartialResponse class */

        size_t CommandPartialResponse::encode(uint8_t *buffer) const {
            size_t length = 10;
            encodeHeader(buffer);
            buffer[7] = PKT_MULTI;
            buffer[8] = mNofParts;
            buffer[9] = mPartIdx;
            std::copy(mMsg.begin(), mMsg.end(), buffer + length);
            length += mMsg.size();
            calculateCrc(buffer, length);
            return length;
        }

        uint8_t CommandPartialResponse::getNofParts() const {
            return mNofParts;
        }

        void CommandPartialResponse::setNofParts(uint8_t nofParts) {
            mNofParts = nofParts;
        }

        uint8_t CommandPartialResponse::getPartIdx() const {
            return mPartIdx;
        }

        void CommandPartialResponse::setPartIdx(uint8_t partIdx) {
            mPartIdx = partIdx;
        }

        const std::string & CommandPartialResponse::getMessage() const {
            return mMsg;
        }

        void CommandPartialResponse::setMessage(const std::string & msg) {
            mMsg = msg;
        }
    }
}
