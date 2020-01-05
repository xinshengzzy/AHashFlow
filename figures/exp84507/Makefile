src1 = /root/traces/CAIDA.equinix-nyc.dirA.20180315-125910.UTC.anon.json
dst1 = ./cdf.caida.20180315-125910.json
src2 = /root/traces/CAIDA.equinix-nyc.dirA.20180315-130000.UTC.anon.json
dst2 = ./cdf.caida.20180315-130000.json
src3 = /root/traces/HGC.20080415000.json
dst3 = ./cdf.hgc.20080415000.json
src4 = /root/traces/HGC.20080415001.json
dst4 = ./cdf.hgc.20080415001.json
prog = ./analyze.py 
zipf_gen = ./zipf_dist_generator.py
dst5 = ./zipf_dist_1.json
dst6 = ./zipf_dist_2.json
n_points = 20
zipf_n = 100000
alpha1 = 0.8
alpha2 = 1.2
analyze:
	$(MAKE) $(dst1)
	$(MAKE) $(dst2)
	$(MAKE) $(dst3)
	$(MAKE) $(dst4)
	$(MAKE) $(dst5)
	$(MAKE) $(dst6)
$(dst1): $(prog) $(src1)
	python $< $(src1) $(n_points) $@
$(dst2): $(prog) $(src2)
	python $< $(src2) $(n_points) $@
$(dst3): $(prog) $(src3)
	python $< $(src3) $(n_points) $@
$(dst4): $(prog) $(src4)
	python $< $(src4) $(n_points) $@
$(dst5): $(zipf_gen) 
	python $< $(zipf_n) $(alpha1) $(n_points) $@
$(dst6): $(zipf_gen) 
	python $< $(zipf_n) $(alpha2) $(n_points) $@
plot:
	 python plot.py
pull:
	 $(MAKE) -C ../../ pull
push:
	 $(MAKE) -C ../../ push
