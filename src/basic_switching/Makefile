APP=basic_switching
build:
	cd $(BUILD) && \
	./autogen.sh && \
	./configure --prefix=$(SDE_INSTALL) --with-tofino P4_NAME=$(APP) P4_PATH=$(SRC)/$(APP)/$(APP).p4 --enable-thrift && \
	make clean && \
	make && \
	make install
run:
	$(SDE)/run_switchd.sh -p $(APP)
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
	echo $(APP)
ptf:
	$(SDE_INSTALL)/bin/veth_setup.sh
	$(SDE_INSTALL)/bin/dma_setup.sh
	cd $(SDE) && \
	./run_p4_tests.sh -p $(APP)
model:
	$(SDE_INSTALL)/bin/veth_setup.sh
	$(SDE_INSTALL)/bin/dma_setup.sh
	$(SDE)/run_tofino_model.sh -p $(APP)
