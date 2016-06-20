# libnet-1.2-rc3-cygwin-static
Compile libnet under cygwin(static)


##Configure

```
./configure --enable-static --prefix=/path/to/libnet \
    CFLAGS="$CFLAGS -I /cygdrive/c/WpdPack/Include/" \
    LIBS="$LIBS -lwsock32 -lws2_32 -liphlpapi -lwpcap -lpacket"
```

> **LIBS="$LIBS -lwsock32 -lws2_32 -liphlpapi -lwpcap -lpacket"** very important.

##Make

When compiling ```"libnet_link_win32.c"``` must be failure.

So rename ```"include/libnet_win32.h"``` to ```"include/libnet.h"``` and rename ```"include/libnet/libnet-structures_win32.h"``` to ```"include/libnet/libnet-structures.h"```.

Then ```make``` command again.

When compiled ```"libnet_link_win32.c"```, will compile fail again.

Now rename ```"include/libnet_origin.h"``` to ```"include/libnet.h"``` and rename ```"include/libnet/libnet-structures_origin.h"``` to ```"include/libnet/libnet-structures.h"```.

Then ```make``` command again.

##Binaries

[libnet-1.2-rc3-cygwin](libnet-1.2-rc3-cygwin) is compiled, include [sample](libnet-1.2-rc3-cygwin/sample).