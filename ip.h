#pragma once

typedef struct {
    unsigned char  flag;
    unsigned char  length;
    unsigned short data;
} IpOption;

typedef struct {
// リトルエンディアン 
    unsigned char headerLength: 4;
    unsigned char version: 4;

// ビッグエンディアン
//    unsigned char version: 4;
//    unsigned char headerLength: 4;

    // サービスタイプ（IPパケットの優先度）
    unsigned char tos;
    // IPパケット全体のサイズをbyte単位で数えたもの
    unsigned short totalLength;
    // IPフラグメンテーション用
    unsigned short id;
    
    unsigned short fragment;
    // Time to Live
    unsigned char ttl;
    // プロトコル番号
    unsigned char protocol;
    // チェックサム
    unsigned short checkSum;
    // 送信元IPアドレス
    unsigned char srcAddress[4];
    // 送信先IPアドレス
    unsigned char destAddress[4];
    
    IpOption option;
} IpHeader;

#define IP_PROTOCOL_ICMP    1
#define IP_PROTOCOL_IGMP    2
#define IP_PROTOCOL_IPINIP  3
#define IP_PROTOCOL_TCP     6
#define IP_PROTOCOL_UDP     17
