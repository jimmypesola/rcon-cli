#ifndef __RCON_HH__
#define __RCON_HH__

#include <sstream>
#include <map>

#define BUF_SIZE 2048
#define CONFIG_FILE_NAME "./rcon.cfg"


namespace Rcon {

    namespace Protocol {
        class Message;
    }

    union OptVal {
        OptVal() {}
        ~OptVal() {}

        bool boolVal;
        int intVal;
        std::string strVal;
    };


    /** RconApp application
     *
     * @remark
     *    This application class does the following:
     *     - Parsing command line parameters.
     *     - Managing the socket and the connection.
     *     - Logging in to the BattlEye RCon server.
     *     - Sending RCon command to the server.
     *     - Allows overriding run() and getOpts methods for customizing/extending behavior.
     */
    class RconApp
    {
        public:
            RconApp() :
                mSocketFd(0),
                mOptions(std::map<std::string, OptVal>()),
                mPassword(std::string())
            {
            }

            virtual ~RconApp(){
            }

            virtual void run(int argc, char *argv[]);

        protected:

            void log(const std::stringstream & msg);

            void error(const std::stringstream & msg);

            virtual void getOpts(int argc, char *argv[]);

            void readConfig(const std::string & cfgFile);

            const std::string & getPassword() const;

            void openConnection(const std::string & ip, const std::string & port);

            void closeConnection();

            void sendPacket(Protocol::Message *msg);

            Protocol::Message *receivePacket();

            int mSocketFd;
            std::map<std::string, OptVal> mOptions;
            std::string mPassword;

        private:
            void printHelp(const std::string & app) const;
    };
}

#endif // __RCON_HH__
