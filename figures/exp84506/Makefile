src1 = /root/traces/CAIDA.equinix-nyc.dirA.20180315-125910.UTC.anon.json
dst1 = ./cdf.caida.20180315-125910.json
src2 = /root/traces/CAIDA.equinix-nyc.dirA.20180315-130000.UTC.anon.json
dst2 = ./cdf.caida.20180315-130000.json
src3 = /root/traces/HGC.20080415000.json
dst3 = ./cdf.hgc.20080415000.json
src4 = /root/traces/HGC.20080415001.json
dst4 = ./cdf.hgc.20080415001.json
prog = ./analyze.py 
analyze:
	$(MAKE) $(dst1)
	$(MAKE) $(dst2)
	$(MAKE) $(dst3)
	$(MAKE) $(dst4)
$(dst1): $(prog) $(src1)
	python $< $(src1) $@
$(dst2): $(prog) $(src2)
	python $< $(src2) $@
$(dst3): $(prog) $(src3)
	python $< $(src3) $@
$(dst4): $(prog) $(src4)
	python $< $(src4) $@
plot:
	 python plot.py
update:
	 $(MAKE) -C ../../ update
