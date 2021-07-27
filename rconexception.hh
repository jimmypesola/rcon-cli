#include <exception>
#include <string>

namespace Rcon {

    /** Exception class
     * @param msg The message to throw with the exception.
     */
    class Exception : virtual public std::exception {
        public:
            explicit Exception(const std::string & msg) : 
                exMsg(msg)
                {}
            virtual ~Exception() throw () {}

            virtual const char *what() const throw () {
                return exMsg.c_str();
            }
        protected:
            std::string exMsg;
    };


    /** ProtocolException class
     * @param msg The message to throw with the exception.
     */
    class ProtocolException : virtual public Exception {
        public:
            explicit ProtocolException(const std::string & msg) :
                Exception(std::string("Protocol Error: " + msg)) {}
    };


    /** SocketException class
     * @param msg The message to throw with the exception.
     */
    class SocketException : virtual public Exception {
        public:
            explicit SocketException(const std::string & msg) :
                Exception(std::string("Socket Error: " + msg)) {}
    };


    /** AppException class
     * @param msg The message to throw with the exception.
     */
    class AppException : virtual public Exception {
        public:
            explicit AppException(const std::string & msg) :
                Exception(std::string("Application Error: " + msg)) {}
    };
}
