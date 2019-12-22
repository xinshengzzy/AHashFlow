header_type measurement_meta_t {
    fields {
        promotion: 1; // indicating variable for resubmit;
        stage: 4; // indicating variable for stage of back inserting;
        stage2: 4; // indicating variable for stage of reporting;
        digest: 8; // digest for differentiating in ancillary table;
        ac_flow_count: 8; // temp storage for flow count of ancillary table;
        flag: 32; // subtract flag used for judging negative or not
        flag2: 32; // subtract flag used for judging negative or not
        fingerprint: 32; // fingerprint for 5-tuple;
        min_flow_count: 32; // minimum flow count of all 3 sub tables of main table;
        max_flow_count: 32; // maximum flow count of all 3 sub tables of main table;
        temp_flow_count: 32; // temp storage for flow count of the current sub table;
        temp_flow_count_2: 32; // temp storage for flow count of the current sub table;
        main_table_1_predicate: 4; // output predicate in main sub table 1;
        main_table_2_predicate: 4; // output predicate in main sub table 2;
        main_table_3_predicate: 4; // output predicate in main sub table 3;
        ancillary_table_predicate: 4; // output predicate in main sub table 1
    }
}

control ingress
{
    apply(generate_fingerprint_t);
    apply(calc_digest_t);
    apply(update_main_table_1_key_t) {
        update_main_table_1_key_action {
            apply(copy_pkt_to_cpu_t_1);
        }
        rewrite_main_table_1_key_action {
            apply(copy_pkt_to_cpu_t_2);
        }
    }
    apply(update_main_table_1_value_t);
    apply(update_main_table_2_key_t) {
        update_main_table_2_key_action {
            apply(copy_pkt_to_cpu_t_3);
        }
        rewrite_main_table_2_key_action {
            apply(copy_pkt_to_cpu_t_4);
        }
    }
    apply(update_main_table_2_value_t) {
        read_main_table_2_value_action {
            apply(min_max_value_subtract_pktcnt_2_t);
            apply(update_min_2_t);
            apply(update_max_2_t);
        }
    }
    apply(update_main_table_3_key_t) {
        update_main_table_3_key_action {
            apply(copy_pkt_to_cpu_t_5);
        }
        rewrite_main_table_3_key_action {
            apply(copy_pkt_to_cpu_t_6);
        }
    }
    apply(update_main_table_3_value_t) {
        read_main_table_3_value_action {
            apply(min_value_subtract_pktcnt_3_t);
            apply(update_min_3_t);
        }
    }
    apply(update_ancillary_table_key_t);
    apply(update_ancillary_table_value_t) {
        update_ancillary_table_value_action {
            apply(min_value_subtract_pktcnt_a_t);
            apply(handle_resubmit_t);
        }
    }
}