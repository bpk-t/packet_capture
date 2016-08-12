#pragma once

typedef struct {
	// 送信元ポート番号
	unsigned short srcPort;
	// 宛先ポート番号
	unsigned short destPort;
	// シーケンス番号
	unsigned int sequenceNum;
	// 確認応答番号
	unsigned int acknowledgmentNum;
	// ヘッダ長
	unsigned int header: 4;
	// 予約済み
	unsigned int reserved: 6;
	
	// コードビット
	struct CodeBit {
		// 緊急フラグ
		unsigned int urg: 1;
		// ack
		unsigned int ack: 1;
		// Push（1:バッファリングしない）
		unsigned int psh: 1;
		// TCP 接続リセット
		unsigned int rst: 1;
		// synchronize
		unsigned int syn: 1;
		// tcp接続終了
		unsigned int fin: 1;
	} codeBit;
	
	// ウィンドウサイズ
	unsigned short windowSize;
    
    // チェックサム
    unsigned short checkSum;
    
	// 緊急ポインタ
	unsigned short urgentPointer;
} TCPHeader;
