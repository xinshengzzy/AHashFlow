./configure --prefix=$SDE_INSTALL enable_thrift=yes
	--with-tofino \
	--with-switchsai \
	--with-cpu-veth \
	-host=i386-linux-gnu CFLAGS=-m32 CXXFLAGS=-m32 LDFLAGS=-m32
make
make install
