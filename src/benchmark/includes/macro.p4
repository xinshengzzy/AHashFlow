// AHashFlow specific parameters
#define HASH_TABLE_IDX_WIDTH 15
#define HASH_TABLE_SIZE 32768 // 0.25 MB of memory, 8 B for each bucket
#define FINGERPRINT_WIDTH 32
#define THRESH 5 // when an evicted flow record has a packet count greater than THRESH, it
	// is exported to the control plane, otherwise it is dropped
#define PRED_COL 1
#define PRED_EMP 2 
#define PRED_MAT 4
#define CTRL_PORT 8082
// parameters about protocols
#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_VLAN 0x8100
#define IPV4_PROMOTION 0xA1
#define IPV4_TCP 0x06
#define IPV4_UDP 0x11
#define PROMOTE_TCP 0x06
#define PROMOTE_UDP 0x11
#define UDP_EXPORT 0x0017
#define EXPORT_HEADER_LEN 22
#define PROMOTE_HEADER_LEN 14
