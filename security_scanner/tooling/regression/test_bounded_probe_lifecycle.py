"""Offline synthetic deadline, worker-cap and partial-coverage checks."""
import copy
import threading
import time
from unittest.mock import patch
import scanner_utils as su
from scanner import SecurityScanner
from scoring_analytics import RiskScorer


def run_checks():
    slot=threading.BoundedSemaphore(1)
    started=threading.Event(); release=threading.Event(); finished=threading.Event()
    def wait_worker():
        started.set(); release.wait(2); finished.set(); return 'late'
    with patch.object(su,'_TIMEOUT_WORKER_SLOTS',slot):
        t=time.monotonic(); out=su.run_with_timeout(wait_worker,timeout=.03)
        assert started.is_set() and out['status']=='timeout' and time.monotonic()-t<.5
        rejected=su.run_with_timeout(lambda:'not-started',timeout=.1)
        assert rejected['status']=='timeout' and 'capacity' in rejected['error']
        release.set(); assert finished.wait(1)
        for _ in range(100):
            if slot.acquire(blocking=False):
                slot.release(); break
            time.sleep(.001)
        else: raise AssertionError('finished worker did not release slot')
        assert su.run_with_timeout(lambda:'ok',timeout=1)=='ok'
        with patch.object(su,'ThreadPoolExecutor',side_effect=RuntimeError('constructor')):
            try: su.run_with_timeout(lambda:None,timeout=.1)
            except RuntimeError: pass
            else: raise AssertionError('constructor error swallowed')
        assert slot.acquire(blocking=False); slot.release()
        class BadExecutor:
            def __init__(self,*a,**k): pass
            def submit(self,*a,**k): raise RuntimeError('submit')
            def shutdown(self,*a,**k): pass
        with patch.object(su,'ThreadPoolExecutor',BadExecutor):
            try: su.run_with_timeout(lambda:None,timeout=.1)
            except RuntimeError: pass
            else: raise AssertionError('submission error swallowed')
        assert slot.acquire(blocking=False); slot.release()
    probe_slot=threading.BoundedSemaphore(2)
    started=threading.Event(); release=threading.Event(); done=threading.Event()
    def probe(n):
        if n==2: started.set(); release.wait(2); done.set(); return 'late'
        return 'positive'
    with patch.object(su,'_PARTIAL_PROBE_SLOTS',probe_slot):
        t=time.monotonic(); got,missing=su.bounded_probe_results(probe,[(1,(1,)),(2,(2,))],max_workers=2,timeout=.05)
        assert started.is_set() and got==[(1,'positive')] and missing==1 and time.monotonic()-t<.5
        assert probe_slot.acquire(blocking=False)
        try:
            got2,missing2=su.bounded_probe_results(probe,[(3,(3,))],max_workers=1,timeout=.1)
            assert got2==[] and missing2==1
        finally: probe_slot.release(); release.set()
        assert done.wait(1)
    per={'192.0.2.1':{'high_risk_protocols':{'status':'error','issues':[]}},
         '192.0.2.2':{'high_risk_protocols':{'status':'completed','issues':['finding'],'critical_count':1}}}
    result=SecurityScanner()._aggregate_ip_results(per,'high_risk_protocols')
    assert result['status']=='completed' and result['critical_count']==1 and result['partial_coverage']
    assert result['unassessed_ips']==[{'ip':'192.0.2.1','status':'error'}]
    # Both statuses are existing failed statuses; with the same preserved data,
    # the scorer must apply the same exclusion and produce the same result.
    base={k:{'status':'completed','score':70} for k in RiskScorer.WEIGHTS}
    base.update(email_security={'status':'completed','score':7},email_hardening={'status':'completed','score':7})
    scores=[]
    for status in ('error','timeout'):
        cats=copy.deepcopy(base); cats['high_risk_protocols']={'status':status,'critical_count':1,'issues':['finding']}
        scores.append(RiskScorer().calculate(cats)[0])
    assert scores[0]==scores[1]
    print('BOUNDED PROBE GREEN: deadline, capacity, releases, failure policy and mixed-IP findings')


if __name__=='__main__':
    run_checks()
