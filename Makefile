CC=gcc
CFLAGS=-I.
DEPS = one_time_pad.h
OBJ = one_time_pad.o

LDIR = -L C:/libsodium-win64/lib
LIB = -l libsodium
DLLDIR = -L C:/libsodium-win64/bin
DLLIBS = -l libsodium-23
#DLDIR = -L C:/libsodium-win64/bin
#DL = -l libsodium-23

PCKDIR = -L C:\libsodium-win64\lib\pkgconfig
CFLAGS= $(pkg-config --cflags libsodium)
LDFLAGS= $(pkg-config --libs libsodium)

#BIN = -L C:\personal_projects\my_encryption\bin
#LIBS2 = -l libsodium-23 -l libgcc_s_seh

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

encryptor: $(OBJ)
	$(CC) -o $@ $^ $(DLLDIR) $(DLLIBS)
#$(LDIR) $(LIB) $(DLLDIR) $(DLLIBS)
#$(PCKDIR) $(CFLAGS) $(LDFLAGS) 
#$(CFLAGS) $(LDFLAGS) -L C:\personal_projects\my_encryption\bin -l libsodium-23 -l libgcc_s_seh-1 -static-libgcc -static-libstdc++
#$(LDIR) $(LIBS) $(CFLAGS) $(LDFLAGS)