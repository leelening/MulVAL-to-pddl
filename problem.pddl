(define(problem pb1)
  (:domain attack-graph)
(:objects s)

(:init
(hacl_10_10_10_1_10_10_10_14_tcp_25 s)
(vulExists_10_10_10_1_CVE_2008_5161_openssh_remoteExploit_privEscalation s)
(hacl_internet_10_10_10_1_tcp_22 s)
(networkServiceInfo_10_10_10_14_openssl_tcp_25_someUser s)
(hacl_internet_10_10_10_14_tcp_25 s)
(attackerLocated_internet s)
(vulExists_10_10_10_14_CVE_2016_0800_openssl_remoteExploit_privEscalation s)
(networkServiceInfo_10_10_10_1_openssh_tcp_22_someUser s)

)

(:goal (and
(execCode_10_10_10_14_someUser s)
(netAccess_10_10_10_14_tcp_25 s)
(netAccess_10_10_10_1_tcp_22 s)
(execCode_10_10_10_1_someUser s)
)
)

)
