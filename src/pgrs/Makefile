P4_NAME=pgrs
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
run:
	$(SDE)/run_switchd.sh -p $(P4_NAME)
push:
	git add -A
	git commit -m "Automatic uploading. No comments!"
	git push
pull:
	git pull
register:
	python ReadRegister.py
send:
	python SendPacket.py
test: 
	echo $(P4_NAME)
ptf:
	cd $(SDE) && \
	./run_p4_tests.sh -p $(P4_NAME)
model:
	$(SDE_INSTALL)/bin/veth_setup.sh
	$(SDE_INSTALL)/bin/dma_setup.sh
	$(SDE)/run_tofino_model.sh -p $(P4_NAME)
