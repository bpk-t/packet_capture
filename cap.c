#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <unistd.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <net/bpf.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <net/if.h>
#include <poll.h>

#include "ethernet.h"
#include "ip.h"
#include "tcp.h"

int main()
{
    char buf[11] = {0};
    int bpf = 0;
    
    for (int i = 0; i < 99; ++i) {
        sprintf(buf, "/dev/bpf%i", i);
        bpf = open(buf, O_RDWR);
        
        if (bpf != -1) break;
    }
    printf("open %s\n", buf);
    
    // ネットワークインタフェースに紐付ける
    struct ifreq interface;
    strcpy(interface.ifr_name, "en0");
    if(ioctl(bpf, BIOCSETIF, &interface) > 0) {
        perror("ioctl BIOCSETIF");
        return errno;
    }
    
    unsigned int one = 1;
    // BIOCIMMEDIATE : 受信したら即時readする
    if (ioctl(bpf, BIOCIMMEDIATE, &one) == -1) {
        perror("ioctl BIOCIMMEDIATE");
        return errno;
    }

    int bufLength = 1;
    // BIOCGBLEN : 受信バッファの必要サイズ
    if (ioctl(bpf, BIOCGBLEN, &bufLength) == -1) {
        perror("ioctl BIOCGBLEN");
        return errno;
    }
    printf("ioctl BIOCGBLEN bufLength=%i\n", bufLength);
    
    // 強制的にプロミスキャスモードにする
    if (ioctl(bpf, BIOCPROMISC, NULL) == -1) {
        perror("ioctl BIOCPROMISC");
        return errno;
    }
    
    int readBytes = 0;
    char *bpfBuffer = malloc(sizeof(char) * bufLength);
    struct bpf_hdr* bpfPacket;
    
    while (1) {    
        // バッファクリア
        memset(bpfBuffer, 0, bufLength);

        readBytes = read(bpf, bpfBuffer, bufLength);
        
        if (readBytes == -1) {
            perror("read()");
            return errno;
        } 
        if (readBytes > 0) {
            char *ptr = 0;
            
            while((int)ptr + sizeof(bpfBuffer) < readBytes) {
                bpfPacket = (struct bpf_hdr*)((long)bpfBuffer + (long)ptr);
                
                //printf("BPF Packet\n");
                //printf(" header: bh_caplen = %d\n", bpfPacket->bh_caplen);
                //printf(" header: bh_datalen = %d\n", bpfPacket->bh_datalen);
                //printf(" header: bh_hdrlen = %d\n", bpfPacket->bh_hdrlen);
                
                printf("--------------------------------------------------\n");
                printf(" Ethernet Frame\n");
                EthernetHeader* ethHeader = (EthernetHeader*)((long)bpfBuffer + (long)ptr + bpfPacket->bh_hdrlen);
                printf("  src mac address: %x:%x:%x:%x:%x:%x\n",
                        ethHeader->srcAddress[0],
                        ethHeader->srcAddress[1],
                        ethHeader->srcAddress[2],
                        ethHeader->srcAddress[3],
                        ethHeader->srcAddress[4],
                        ethHeader->srcAddress[5]);

                printf("  dest mac address: %x:%x:%x:%x:%x:%x\n",
                        ethHeader->destAddress[0],
                        ethHeader->destAddress[1],
                        ethHeader->destAddress[2],
                        ethHeader->destAddress[3],
                        ethHeader->destAddress[4],
                        ethHeader->destAddress[5]);
                
                if (ethHeader->type == TYPE_IPV4) {
                    printf("  type: IPv4, %x\n", ethHeader->type);
                    
                    IpHeader* ip = (IpHeader*)((long)ethHeader + sizeof(EthernetHeader));
                
                    printf(" IP Frame\n");
                    printf("  headerLength: %d\n", ip->headerLength * 4);
                    printf("  version: %d\n", ip->version);
                    printf("  ttl: %d\n", ip->ttl);
                    printf("  dest ip: %d.%d.%d.%d\n",
                        ip->destAddress[0],
                        ip->destAddress[1],
                        ip->destAddress[2],
                        ip->destAddress[3]);
                    printf("  src ip: %d.%d.%d.%d\n",
                        ip->srcAddress[0],
                        ip->srcAddress[1],
                        ip->srcAddress[2],
                        ip->srcAddress[3]);
                    
                    if (ip->protocol == IP_PROTOCOL_TCP) {
                        TCPHeader* tcp = (TCPHeader*)((long)ip + (ip->headerLength * 4));
                        printf(" TCP Frame\n");
                        printf("  dest port: %d\n", tcp->destPort);
                        printf("  src port: %d\n", tcp->srcPort);
                    }
                } else {
                    printf("  type: Other, %x\n", ethHeader->type);
                }
                
                // 次のパケットへ移動（BPF_WORDALIGNを利用することでパディングを考慮してくれる）
                ptr += BPF_WORDALIGN(bpfPacket->bh_hdrlen + bpfPacket->bh_caplen);
            }
        }
    }
    free(bpfBuffer);
    
    return 0;
}