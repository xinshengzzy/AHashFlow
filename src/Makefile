#P4_NAME=emulation
#P4_NAME=basic_switching
#P4_NAME=multi_device
#P4_NAME=multicast_scale
P4_NAME=AHashFlow
#P4_NAME=HashFlow
#P4_NAME=resubmit
#P4_NAME=benchmark
#P4_NAME=myswitch
#P4_NAME=Elastic
build:
	cd $(BUILD) && \
	./autogen.sh && \
	./configure --prefix=$(SDE_INSTALL) \
		--with-tofino \
		--enable-thrift \
		P4_VERSION=p4-14 \
		P4_ARCHITECTURE=tna \
		P4_NAME=$(P4_NAME) \
		P4_PATH=$(SRC)/$(P4_NAME)/$(P4_NAME).p4 && \
	make uninstall && \
	make clean && \
	make && \
	make install
uninstall:
	cd $(BUILD) && \
	./autogen.sh && \
	./configure --prefix=$(SDE_INSTALL) \
		--with-tofino \
		--enable-thrift \
		P4_VERSION=p4-14 \
		P4_ARCHITECTURE=tna \
		P4_NAME=$(P4_NAME) \
		P4_PATH=$(SRC)/$(P4_NAME)/$(P4_NAME).p4 && \
	make uninstall && \
	make clean
run:
	pkill bf_switchd || true
	pkill run_switchd.sh || true
	$(SDE)/run_switchd.sh -p $(P4_NAME) &
configure:
	bfshell -f $(SRC)/$(P4_NAME)/commands.txt
push:
	git add -A
	git commit -m "Automatic uploading. No comments!"
	git push
pull:
	git pull
register:
	python ./$(P4_NAME)/ReadRegister.py
send:
	python SendPacket.py
ptf:
	cd $(SDE) && \
	python $(SDE_INSTALL)/lib/python2.7/site-packages/p4testutils/run_ptf_tests.py \
		--test-dir $(SRC)/$(P4_NAME)/ptf-tests
model:
	$(SDE_INSTALL)/bin/veth_setup.sh
	$(SDE_INSTALL)/bin/dma_setup.sh
	$(SDE)/run_tofino_model.sh -p $(P4_NAME)
