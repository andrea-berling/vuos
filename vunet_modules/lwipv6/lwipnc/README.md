# Netcat demo

The following is a demo of a netcat utility based on lwipv6. There are three versions: one that uses
lwip\_select, one that use lwip\_poll, and a last one that uses the epoll framework.

To get it working you will need to first create a tap interface:
```bash
    # ip tuntap add tap0 mode tap user your_username
```

You will then need to modify the ip address and the netmask set inside the lwipnc code. Anything
goes, as long as it is coherent with your machine's network configuration and there is a route for
the set ip address on your machine. For example, if your machine is part of a 192.168.0.0 network,
with a 255.255.255.0 netmask, you may set the ip address to 192.168.0.150 and add a route for the
program with the following command:
```bash
    # ip route add 192.168.0.150 dev tap0
```

Then you will need to compile the netcat program. You may use the following commands. You will need
to have CMake versione >= 3.8. Make sure to run them in the lwipv6 directory (one level up)
```bash
    $ mkdir build
    $ cd build
    $ cmake ..
    $ make
```

At the end of the process you will find the executables in build/lwipnc

Then you will need to make sure your system knows where to find the needed libraries. If you have
already installed lwipv6 and vpoll you don't need to do anything. Otherwise you may use the
following command:
```bash
    $ export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:some_path/lwipv6/build/vpoll:some_path/lwipv6/build/lwip-contrib/ports/unix/proj/lib
```
where some\_path is the absolute path that leads to lwipv6

You will then need to 
Finally, you can open a second terminal and run the following command:
```bash
    $ nc -l -p 9999
```

You can then move into `build/lwipnc` and start lwipnc with the ip address of your machine and the
port 9999 as parameters and use it:
```bash
    $ ./lwipnc-epoll your_ip_address 9999
```

Note: the set route may be unset because of lwinc setting the interface up. You may need to add it
again after using lwipnc.
