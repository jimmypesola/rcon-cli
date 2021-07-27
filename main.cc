#include "rcon.hh"
#include "rconexception.hh"
#include <iostream>

int main(int argc, char *argv[])
{
    try {
        Rcon::RconApp().run(argc, argv);
    } catch (Rcon::AppException e) {
        return 1;
    } catch (Rcon::Exception e) {
        std::cerr << e.what() << std::endl;
        return 1;
    }
    return 0;
}
