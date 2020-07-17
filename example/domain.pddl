(define(domain attack_graph)
    (:requirements :strips)

(:predicates
(hacl_10_10_10_1_10_10_10_14_tcp_25 ?x)
 (vulExists_10_10_10_1_CVE_2008_5161_openssh_remoteExploit_privEscalation ?x)
 (hacl_internet_10_10_10_1_tcp_22 ?x)
 (networkServiceInfo_10_10_10_14_openssl_tcp_25_someUser ?x)
 (execCode_10_10_10_1_someUser ?x)
 (vulExists_10_10_10_14_CVE_2016_0800_openssl_remoteExploit_privEscalation ?x)
 (networkServiceInfo_10_10_10_1_openssh_tcp_22_someUser ?x)
 (netAccess_10_10_10_1_tcp_22 ?x)
 (netAccess_10_10_10_14_tcp_25 ?x)
 (hacl_internet_10_10_10_14_tcp_25 ?x)
 (execCode_10_10_10_14_someUser ?x)
 (attackerLocated_internet ?x)

)

(:action RULE_5_multi_hop_access_12
:parameters (?x)
:precondition (and
 (hacl_10_10_10_1_10_10_10_14_tcp_25 ?x)
 (execCode_10_10_10_1_someUser ?x)
)
:effect (and
 (netAccess_10_10_10_14_tcp_25 ?x)
)
)

(:action RULE_6_direct_network_access_14
:parameters (?x)
:precondition (and
 (hacl_internet_10_10_10_14_tcp_25 ?x)
 (attackerLocated_internet ?x)
)
:effect (and
 (netAccess_10_10_10_14_tcp_25 ?x)
)
)

(:action RULE_2_remote_exploit_of_a_server_program_2
:parameters (?x)
:precondition (and
 (netAccess_10_10_10_1_tcp_22 ?x)
 (networkServiceInfo_10_10_10_1_openssh_tcp_22_someUser ?x)
 (vulExists_10_10_10_1_CVE_2008_5161_openssh_remoteExploit_privEscalation ?x)
)
:effect (and
 (execCode_10_10_10_1_someUser ?x)
)
)

(:action RULE_6_direct_network_access_4
:parameters (?x)
:precondition (and
 (hacl_internet_10_10_10_1_tcp_22 ?x)
 (attackerLocated_internet ?x)
)
:effect (and
 (netAccess_10_10_10_1_tcp_22 ?x)
)
)

(:action RULE_2_remote_exploit_of_a_server_program_10
:parameters (?x)
:precondition (and
 (netAccess_10_10_10_14_tcp_25 ?x)
 (networkServiceInfo_10_10_10_14_openssl_tcp_25_someUser ?x)
 (vulExists_10_10_10_14_CVE_2016_0800_openssl_remoteExploit_privEscalation ?x)
)
:effect (and
 (execCode_10_10_10_14_someUser ?x)
)
)

)
