CC                              =   gcc

MKDIR                           =   mkdir -p
RM                              =   rm -fr
CP                              =   cp

DAQDIR                          =   /usr/lib/daq

CFLAGS                          =   -c -g -MMD -fpic -Wall -Werror -DBUILDING_SO -I./
CFLAGS                         +=   $(pkg-config --cflags libdaq)

CWD                             =   ./
OBJD                            =   obj

TGT                             =   daq_gwlb.so

SRCS                            =   daq_gwlb.c
OBJS                            =   $(patsubst %.c,  $(OBJD)/%.o, $(SRCS))

all: $(TGT)

install: $(TGT)
	$(CP) $(TGT) $(DAQDIR)

$(TGT): $(OBJD) $(OBJS)
	$(CC) -export-dynamic -shared $(OBJS) -o $@

$(OBJD):
	$(MKDIR) $@

$(OBJD)/%.o: %.c
	$(CC) $(CFLAGS) $< -o $@

clean:
	$(RM) $(TGT) $(OBJD)

.PHONY: clean

-include $(DEPS)
