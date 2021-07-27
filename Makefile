OBJFILES = main.o rcon.o rconmsg.o rconexception.o

FLAGS = -DLINUX

LDLIBS = -dH -lz

APP = rcon

.PHONY: all
all: $(OBJFILES) $(APP)

$(APP): $(OBJFILES)
	g++ -o $@ $(OBJFILES) $(LDLIBS)

%.o: %.cc
	g++ $(FLAGS) -c $<

clean:
	rm -f $(OBJFILES) $(APP)
