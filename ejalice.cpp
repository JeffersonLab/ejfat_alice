#include "ejalice.h"



#ifdef __linux__
#ifndef _GNU_SOURCE
        #define _GNU_SOURCE
    #endif

    #include <sched.h>
    #include <pthread.h>
#endif


using namespace ejfat;

static void sendLB(char* buf, uint64_t bufSize, const char* host,
                   const char* interface, uint64_t tick, uint16_t streamId,
                   const bool* debug) {
    if (!*host) {
        // Default to sending to local host
        host = "127.0.0.1";
    }

    int mtu = 0;
    // Break data into multiple packets of max MTU size.
    // If the mtu was not set, attempt to get it programmatically.
    if (mtu == 0) {
        if (!*interface) {
            mtu = getMTU("eth0", debug);
        }
        else {
            mtu = getMTU(interface, debug);
        }
    }

    // If we still can't figure this out, set it to a safe value.
    if (mtu == 0) {
        mtu = 1400;
    }

    uint32_t offset = 0;
    int version = 2;
    int protocol = 1;
    int entropy = 0;
    bool firstBuffer = true;
    bool lastBuffer  = true;

    struct sockaddr_in serverAddr{};

    // UDP socket
    int udpSocket;

    // 20 bytes = normal IPv4 packet header (60 is max), 8 bytes = max UDP packet header
    int maxUdpPayload = mtu - 20 - 8 - HEADER_BYTES;

    // Create UDP socket
    if ((udpSocket = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("creating IPv4 client socket");
    }

    // Configure socket settings
    socklen_t size = sizeof(int);
    int sendBufBytes = 0;
    getsockopt(udpSocket, SOL_SOCKET, SO_SNDBUF, &sendBufBytes, &size);
    if (debug) fprintf(stderr, "UDP socket send buffer = %d bytes\n", sendBufBytes);

    // Configure settings in address struct
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(EjLbPort);
    serverAddr.sin_addr.s_addr = inet_addr(host);
    memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);

    // Connecting to the socket
    fprintf(stderr, "Connection socket to host %s, EjLbPort %hu\n", host, EjLbPort);
    int err = connect(udpSocket, (const struct sockaddr *) &serverAddr, sizeof(struct sockaddr_in));
    if (err < 0) {
        perror("Error connecting UDP socket:");
        close(udpSocket);
    }

    err = sendPacketizedBufferFast(buf, bufSize, maxUdpPayload, udpSocket,
                                   tick, protocol, entropy, version, streamId,
                                   &offset,firstBuffer, lastBuffer, debug);

    if (err < 0) {
        // Should be more info in errno
        fprintf(stderr, "\nsendPacketizedBuffer: errno = %d, %s\n\n", errno, strerror(errno));
        exit(1);
    }

}
