// macro.p4
// AHashFlow specific parameters
#define MAIN_TABLE_IDX_WIDTH 13
#define M_TABLE_1_SIZE 8192
#define M_TABLE_2_SIZE 8192
#define M_TABLE_3_SIZE 8192
#define A_TABLE_IDX_WIDTH 14
#define A_TABLE_SIZE 16384
#define B_TABLE_IDX_WIDTH 14
#define B_TABLE_SIZE 16384
#define DIGEST_WIDTH 8
#define FINGERPRINT_WIDTH 32
#define GAMMA 5
#define PRED_COL 1
#define PRED_EMP 2 
#define PRED_MAT 4
#define CTRL_IP 0x0a00000b
#define CTRL_SRC_IP 0x0a00000a
#define CTRL_PORT 8082
// parameters about protocols
#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_VLAN 0x8100
#define IPV4_TCP 0x06
#define IPV4_UDP 0x11
#define UDP_EXPORT 0x1111
#define EXPORT_HEADER_LEN 38
