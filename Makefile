NAME	= send-arp
CC		= g++
LDLIBS	=-lpcap
RM		= rm -rf
SRCS	= main.cpp \
		  arphdr.cpp \
		  ethhdr.cpp \
		  ip.cpp \
		  mac.cpp \
		  utils.cpp
OBJS	= $(SRCS:.cpp=.o)

all : $(NAME)

$(NAME) : $(OBJS)
	$(CC) $^  $(LDLIBS) -o $@

%.o : %.cpp	
	$(CC) -c $< -o $@ $(LDLIBS)

clean:
	$(RM) $(NAME)
	$(RM) $(OBJS)
