#pragma once

typedef struct {
    // 送信先Macアドレス
    unsigned char destAddress[6];
    // 送信元Macアドレス
    unsigned char srcAddress[6];
    // 種類
    unsigned short type;
} EthernetHeader;

/* リトルエンディアン版のTYPE */
#define TYPE_IPV4        0x0008
#define TYPE_ARP         0x0608
#define TYPE_RARP        0x3580
#define TYPE_APPLE_TALK  0x9b80
#define TYPE_IEEE8021Q   0x0081
#define TYPE_NETWARE_IPX 0x3781
