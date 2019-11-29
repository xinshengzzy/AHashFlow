ucli
pm
port-add -/- 40G NONE
port-enb -/-
..
bf_pltfm
qsfp
qsfp-lpmode-hw 5 0
qsfp-lpmode-hw 9 0
..
..
exit
pd-myswitch
pd forward add_entry set_egr ig_intr_md_ingress_port 60 action_egress_spec 160
pd forward add_entry set_egr ig_intr_md_ingress_port 160 action_egress_spec 60
exit
