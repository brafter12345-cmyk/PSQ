"""Synthetic partial results across the five bounded network probe groups."""
from unittest.mock import patch
import checkers_network as cn


def run_checks():
    ct=cn.SubdomainChecker._CTNames(); ct.answered=True; ct.foreign=frozenset()
    sub=cn.SubdomainChecker()
    replies=[([('api.example.test',['192.0.2.1'])],1),
             ([('api.example.test',['192.0.2.1'])],1),
             ([('api.example.test',{'subdomain':'api.example.test','service':'fake','cname_target':'example.invalid'})],1)]
    with patch.object(sub,'_ct_crtsh',return_value=ct), patch.object(sub,'_ct_certspotter',return_value=ct), patch.object(sub,'_wildcard_ips',return_value=set()), patch.object(cn,'bounded_probe_results',side_effect=replies):
        out=sub.check('example.test')
    assert out['status']=='timeout' and out['partial_coverage']
    assert out['incomplete_probes']=={'brute_force':1,'resolution':1,'takeover':1}
    assert len(out['takeover_vulnerable'])==1
    port={'port':443,'service':'HTTPS','risk':'info'}
    with patch.object(cn,'bounded_probe_results',return_value=([(443,port)],1)), patch.object(cn,'is_saturated_host',return_value=False), patch.object(cn,'DNS_AVAILABLE',False), patch.object(cn,'public_ip',return_value=True), patch.object(cn.DNSInfrastructureChecker,'_fingerprint_server',return_value={}):
        dns=cn.DNSInfrastructureChecker().check('example.test','192.0.2.1')
    assert dns['status']=='timeout' and dns['partial_coverage'] and dns['open_ports'][0]['port']==443
    service={'port':3389,'service':'RDP','insurance_risk':'synthetic'}
    with patch.object(cn,'bounded_probe_results',return_value=([(3389,service)],1)), patch.object(cn,'is_saturated_host',return_value=False), patch.object(cn,'public_ip',return_value=True):
        hrp=cn.HighRiskProtocolChecker().check('example.test','192.0.2.1')
    assert hrp['status']=='timeout' and hrp['partial_coverage'] and hrp['critical_count']==1
    from test_partial_dns_pdf import run_checks as check_pdf_wording
    check_pdf_wording()
    print('PARTIAL PROBES GREEN: five groups retain completed findings')


if __name__=='__main__':
    run_checks()
