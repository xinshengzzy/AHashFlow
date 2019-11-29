build:
	cd $(BUILD) && \
	./autogen.sh && \
	./configure --prefix=$(SDE_INSTALL) --with-tofino P4_NAME=mirror_test P4_PATH=$(SRC)/mirror_test/mirror_test.p4 --enable-thrift && \
	make clean && \
	make && \
	make install
run:
	/root/bf-sde-8.2.0/run_switchd.sh -p mirror_test
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
test: test.cc
	g++ test.cc -o test
	./test
ptf:
	/root/bf-sde-8.2.0/run_p4_tests.sh -p mirror_test
