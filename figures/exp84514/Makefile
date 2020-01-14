main:
	python3 main.py 4 5 2 &
	python3 main.py 6 7 2 &
	python3 main.py 8 9 2 &
	python3 main.py 10 11 2 &
	python3 main.py 12 13 2 &
	python3 main.py 14 15 2 &
plot:
	 python3 plot.py
update:
	 $(MAKE) -C ../../ update
test:
	 python3 test.py 4 5
clean:
	rm *.json || true
	rm *.pdf || true
	rm *.png || true
