from thrift.protocol import TMultiplexedProtocol
from thrift.protocol import TBinaryProtocol
from thrift.transport import TSocket
from thrift.transport import TTransport
import conn_mgr_pd_rpc.conn_mgr
from res_pd_rpc.ttypes import *
from ptf.thriftutils import *
from knet_mgr_test.p4_pd_rpc.ttypes import *
import knet_mgr_test.p4_pd_rpc.knet_mgr_test as knet_mgr_test

thrift_server = "localhost"
#transport = TSocket.TSocket(thrift_server, 9090)
transport = TSocket.TSocket(thrift_server, 9090)
transport = TTransport.TBufferedTransport(transport)
transport.open()
bprotocol = TBinaryProtocol.TBinaryProtocol(transport)
conn_mgr_protocol = TMultiplexedProtocol.TMultiplexedProtocol(bprotocol, "conn_mgr")
conn_mgr = conn_mgr_pd_rpc.conn_mgr.Client(conn_mgr_protocol)
sess_hdl = conn_mgr.client_init()
dev = 0
dev_tgt = DevTarget_t(dev, hex_to_i16(0xFFFF))

p4_prefix = "knet_mgr_test"
p4_protocol = TMultiplexedProtocol.TMultiplexedProtocol(bprotocol, p4_prefix) 
client = knet_mgr_test.Client(p4_protocol)
flag = knet_mgr_test_register_flags_t(read_hw_sync = True)
#res = client.register_read_pktcnt(sess_hdl, dev_tgt, 0, flag)
#client.register_write_main_table_1_value(sess_hdl, dev_tgt, 0, 5)
res = client.register_read_cntr(sess_hdl, dev_tgt, 0, flag)
print "res:", res
conn_mgr.client_cleanup(hex_to_i32(sess_hdl))
