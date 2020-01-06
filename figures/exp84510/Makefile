src = /root/traces/CAIDA.equinix-nyc.dirA.20180315-130000.UTC.anon.json
dst1 = ./result.scheme.1.caida.20180315-130000.json
dst2 = ./result.scheme.2.caida.20180315-130000.json
dst3 = ./result.scheme.3.caida.20180315-130000.json
dst4 = ./result.scheme.4.caida.20180315-130000.json
dst5 = ./result.scheme.5.caida.20180315-130000.json
dst6 = ./result.scheme.6.caida.20180315-130000.json
dst7 = ./result.scheme.7.caida.20180315-130000.json
dst8 = ./result.scheme.8.caida.20180315-130000.json
dst9 = ./result.scheme.9.caida.20180315-130000.json
dst10 = ./result.scheme.10.caida.20180315-130000.json
dst11 = ./result.scheme.11.caida.20180315-130000.json
dst12 = ./result.scheme.12.caida.20180315-130000.json
dst13 = ./result.scheme.13.caida.20180315-130000.json
dst14 = ./result.scheme.14.caida.20180315-130000.json
dst15 = ./result.scheme.15.caida.20180315-130000.json
dst16 = ./result.scheme.16.caida.20180315-130000.json
dst17 = ./result.scheme.17.caida.20180315-130000.json
dst18 = ./result.scheme.18.caida.20180315-130000.json
dst19 = ./result.scheme.19.caida.20180315-130000.json
prog = ./analyze.py 
this = ./Makefile
analyze:
	$(MAKE) $(dst1)
#	$(MAKE) $(dst2)
#	$(MAKE) $(dst3)
#	$(MAKE) $(dst4)
#	$(MAKE) $(dst5)
#	$(MAKE) $(dst6)
#	$(MAKE) $(dst7)
#	$(MAKE) $(dst8)
#	$(MAKE) $(dst9)
#	$(MAKE) $(dst10)
	$(MAKE) $(dst11)
	$(MAKE) $(dst12)
	$(MAKE) $(dst13)
	$(MAKE) $(dst14)
	$(MAKE) $(dst15)
	$(MAKE) $(dst16)
	$(MAKE) $(dst17)
	$(MAKE) $(dst18)
	$(MAKE) $(dst19)
$(dst1): $(prog) $(src)
	python $< $(src) $@ 1
$(dst2): $(prog) $(src)
	python $< $(src) $@ 2
$(dst3): $(prog) $(src)
	python $< $(src) $@ 3
$(dst4): $(prog) $(src)
	python $< $(src) $@ 4
$(dst5): $(prog) $(src)
	python $< $(src) $@ 5
$(dst6): $(prog) $(src)
	python $< $(src) $@ 6
$(dst7): $(prog) $(src)
	python $< $(src) $@ 7
$(dst8): $(prog) $(src)
	python $< $(src) $@ 8
$(dst9): $(prog) $(src)
	python $< $(src) $@ 9
$(dst10): $(prog) $(src)
	python $< $(src) $@ 10
$(dst11): $(prog) $(src)
	python $< $(src) $@ 11
$(dst12): $(prog) $(src)
	python $< $(src) $@ 12
$(dst13): $(prog) $(src)
	python $< $(src) $@ 13
$(dst14): $(prog) $(src)
	python $< $(src) $@ 14
$(dst15): $(prog) $(src)
	python $< $(src) $@ 15
$(dst16): $(prog) $(src)
	python $< $(src) $@ 16
$(dst17): $(prog) $(src)
	python $< $(src) $@ 17
$(dst18): $(prog) $(src)
	python $< $(src) $@ 18
$(dst19): $(prog) $(src)
	python $< $(src) $@ 19
plot:
	 python plot.py
update:
	 $(MAKE) -C ../../ update
test:
	 python test.py
