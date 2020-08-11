(define(domain attack_graph)
    (:requirements :strips)

(:predicates
(execcode_10_10_10_14_someuser ?x)
 (netaccess_10_10_10_2_tcp_22 ?x)
 (attackerlocated_internet ?x)
 (networkserviceinfo_10_10_10_2_openssh_tcp_22_someuser ?x)
 (execcode_10_10_10_2_someuser ?x)
 (networkserviceinfo_10_10_10_1_openssh_tcp_22_someuser ?x)
 (vulexists_10_10_10_2_cve_2015_2808_safari_remoteexploit_privescalation ?x)
 (hacl_10_10_10_2_10_10_10_14_tcp_25 ?x)
 (networkserviceinfo_10_10_10_2_safari_tcp_25_someuser ?x)
 (netaccess_10_10_10_1_tcp_22 ?x)
 (vulexists_10_10_10_2_cve_2008_5161_openssh_remoteexploit_privescalation ?x)
 (networkserviceinfo_10_10_10_1_safari_tcp_25_someuser ?x)
 (execcode_10_10_10_1_someuser ?x)
 (hacl_internet_10_10_10_1_tcp_25 ?x)
 (hacl_10_10_10_1_10_10_10_2_tcp_25 ?x)
 (networkserviceinfo_10_10_10_14_openssl_tcp_25_someuser ?x)
 (netaccess_10_10_10_14_tcp_25 ?x)
 (vulexists_10_10_10_1_cve_2008_5161_openssh_remoteexploit_privescalation ?x)
 (netaccess_10_10_10_2_tcp_25 ?x)
 (hacl_internet_10_10_10_1_tcp_22 ?x)
 (vulexists_10_10_10_14_cve_2016_0800_openssl_remoteexploit_privescalation ?x)
 (hacl_10_10_10_1_10_10_10_2_tcp_22 ?x)
 (vulexists_10_10_10_1_cve_2015_2808_safari_remoteexploit_privescalation ?x)
 (netaccess_10_10_10_1_tcp_25 ?x)

)

(:action rule_2_remote_exploit_of_a_server_program_16
:parameters (?x)
:precondition (and
 (netaccess_10_10_10_14_tcp_25 ?x)
 (networkserviceinfo_10_10_10_14_openssl_tcp_25_someuser ?x)
 (vulexists_10_10_10_14_cve_2016_0800_openssl_remoteexploit_privescalation ?x)
)
:effect (and
 (execcode_10_10_10_14_someuser ?x)
)
)

(:action rule_6_direct_network_access_11
:parameters (?x)
:precondition (and
 (hacl_internet_10_10_10_1_tcp_25 ?x)
 (attackerlocated_internet ?x)
)
:effect (and
 (netaccess_10_10_10_1_tcp_25 ?x)
)
)

(:action rule_5_multi_hop_access_18
:parameters (?x)
:precondition (and
 (hacl_10_10_10_2_10_10_10_14_tcp_25 ?x)
 (execcode_10_10_10_2_someuser ?x)
)
:effect (and
 (netaccess_10_10_10_14_tcp_25 ?x)
)
)

(:action rule_2_remote_exploit_of_a_server_program_2
:parameters (?x)
:precondition (and
 (netaccess_10_10_10_1_tcp_22 ?x)
 (networkserviceinfo_10_10_10_1_openssh_tcp_22_someuser ?x)
 (vulexists_10_10_10_1_cve_2008_5161_openssh_remoteexploit_privescalation ?x)
)
:effect (and
 (execcode_10_10_10_1_someuser ?x)
)
)

(:action rule_5_multi_hop_access_29
:parameters (?x)
:precondition (and
 (hacl_10_10_10_1_10_10_10_2_tcp_25 ?x)
 (execcode_10_10_10_1_someuser ?x)
)
:effect (and
 (netaccess_10_10_10_2_tcp_25 ?x)
)
)

(:action rule_2_remote_exploit_of_a_server_program_27
:parameters (?x)
:precondition (and
 (netaccess_10_10_10_2_tcp_25 ?x)
 (networkserviceinfo_10_10_10_2_safari_tcp_25_someuser ?x)
 (vulexists_10_10_10_2_cve_2015_2808_safari_remoteexploit_privescalation ?x)
)
:effect (and
 (execcode_10_10_10_2_someuser ?x)
)
)

(:action rule_2_remote_exploit_of_a_server_program_9
:parameters (?x)
:precondition (and
 (netaccess_10_10_10_1_tcp_25 ?x)
 (networkserviceinfo_10_10_10_1_safari_tcp_25_someuser ?x)
 (vulexists_10_10_10_1_cve_2015_2808_safari_remoteexploit_privescalation ?x)
)
:effect (and
 (execcode_10_10_10_1_someuser ?x)
)
)

(:action rule_6_direct_network_access_4
:parameters (?x)
:precondition (and
 (hacl_internet_10_10_10_1_tcp_22 ?x)
 (attackerlocated_internet ?x)
)
:effect (and
 (netaccess_10_10_10_1_tcp_22 ?x)
)
)

(:action rule_2_remote_exploit_of_a_server_program_21
:parameters (?x)
:precondition (and
 (netaccess_10_10_10_2_tcp_22 ?x)
 (networkserviceinfo_10_10_10_2_openssh_tcp_22_someuser ?x)
 (vulexists_10_10_10_2_cve_2008_5161_openssh_remoteexploit_privescalation ?x)
)
:effect (and
 (execcode_10_10_10_2_someuser ?x)
)
)

(:action rule_5_multi_hop_access_23
:parameters (?x)
:precondition (and
 (hacl_10_10_10_1_10_10_10_2_tcp_22 ?x)
 (execcode_10_10_10_1_someuser ?x)
)
:effect (and
 (netaccess_10_10_10_2_tcp_22 ?x)
)
)

)
