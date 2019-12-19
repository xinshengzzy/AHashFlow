from thrift.protocol import TMultiplexedProtocol
from thrift.protocol import TBinaryProtocol
from thrift.transport import TSocket
from thrift.transport import TTransport
import conn_mgr_pd_rpc.conn_mgr
from res_pd_rpc.ttypes import *
from ptf.thriftutils import *
from basic_switching.p4_pd_rpc.ttypes import *
import basic_switching.p4_pd_rpc.basic_switching as basic_switching

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

p4_prefix = "basic_switching"
p4_protocol = TMultiplexedProtocol.TMultiplexedProtocol(bprotocol, p4_prefix) 
client = basic_switching.Client(p4_protocol)
flag = basic_switching_register_flags_t(read_hw_sync = True)
#res = client.register_read_pktcnt(sess_hdl, dev_tgt, 0, flag)
#client.register_write_cntr(sess_hdl, dev_tgt, 0, 5)
'''
res = client.register_read_cntr(sess_hdl, dev_tgt, 0, flag)
print "pkt_cnt:", res
res = client.register_read_cntr(sess_hdl, dev_tgt, 5, flag)
print "promote_cnt:", res
res = client.register_read_cntr_noop(sess_hdl, dev_tgt, 0, flag)
print "cntr_noop:", res
res = client.register_read_cntr_noop(sess_hdl, dev_tgt, 1, flag)
print "cntr_drop:", res
res = client.register_read_cntr_meta(sess_hdl, dev_tgt, 0, flag)
print "measurement_meta.cnt:", res
'''
#res = client.register_read_cntr1(sess_hdl, dev_tgt, 0, flag)
#print "cntr1:", res
#res = client.register_read_cntr2(sess_hdl, dev_tgt, 0, flag)
#print "cntr2:", res
#res = client.register_read_cntr1(sess_hdl, dev_tgt, 0, flag)
#print "cntr1[0]:", res
#res = client.register_read_cntr2(sess_hdl, dev_tgt, 0, flag)
#print "cntr2[0]:", res
res = client.register_read_cntr1(sess_hdl, dev_tgt, 0, flag)
print "cntr1[0]:", res
#res = client.register_read_cntr4(sess_hdl, dev_tgt, 0, flag)
#print "cntr4[0]:", res
#for i in range(min(res)):
#    etherType = client.register_read_cntr3(sess_hdl, dev_tgt, i, flag)
#    print "etherType:", etherType
'''
res = client.register_read_cntr4(sess_hdl, dev_tgt, 0, flag)
print "cntr4:", res
res = client.register_read_cntr5(sess_hdl, dev_tgt, 0, flag)
print "cntr5:", res
'''
'''
res = client.register_read_cntr6(sess_hdl, dev_tgt, 0, flag)
print "cntr6:", res
res = client.register_read_cntr7(sess_hdl, dev_tgt, 0, flag)
print "cntr7:", res
res = client.register_read_cntr8(sess_hdl, dev_tgt, 0, flag)
print "cntr8:", res
res = client.register_read_cntr9(sess_hdl, dev_tgt, 0, flag)
print "cntr9:", res
res = client.register_read_cntr10(sess_hdl, dev_tgt, 0, flag)
print "cntr10:", res
res = client.register_read_cntr11(sess_hdl, dev_tgt, 0, flag)
print "cntr11:", res
res = client.register_read_cntr12(sess_hdl, dev_tgt, 0, flag)
print "cntr12:", res
'''
'''
res = client.register_read_cntr13(sess_hdl, dev_tgt, 0, flag)
print "cntr13:", res
res = client.register_read_cntr14(sess_hdl, dev_tgt, 0, flag)
print "cntr14:", res
res = client.register_read_cntr15(sess_hdl, dev_tgt, 0, flag)
print "cntr15:", res
res = client.register_read_cntr16(sess_hdl, dev_tgt, 0, flag)
print "cntr16:", res
res = client.register_read_cntr17(sess_hdl, dev_tgt, 0, flag)
print "cntr17:", res
res = client.register_read_cntr18(sess_hdl, dev_tgt, 0, flag)
print "cntr18:", res
res = client.register_read_cntr19(sess_hdl, dev_tgt, 0, flag)
print "cntr19:", res
#res = client.register_read_cntr20(sess_hdl, dev_tgt, 0, flag)
#print "cntr20:", res
'''
conn_mgr.client_cleanup(hex_to_i32(sess_hdl))
