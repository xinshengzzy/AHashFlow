// Elastic specific parameters
// the total memory for registers is 0.25MB
#define HEAVY_TABLE_1_SIZE 8192
#define HEAVY_TABLE_2_SIZE 4096
#define HEAVY_TABLE_3_SIZE 4096
#define LIGHT_TABLE_SIZE 16384
#define HEAVY_TABLE_1_IDX_WIDTH 13
#define HEAVY_TABLE_2_IDX_WIDTH 12
#define HEAVY_TABLE_3_IDX_WIDTH 12
#define LIGHT_TABLE_IDX_WIDTH 14
#define NUM_HEAVY_TABLE 4
#define FINGERPRINT_WIDTH 32
#define LAMBDA 32
#define PRED_COL 1
#define PRED_EMP 2 
#define PRED_MAT 4
#define CTRL_PORT 8082
#define N_SHIFT 5
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
