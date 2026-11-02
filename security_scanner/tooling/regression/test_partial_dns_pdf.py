"""Offline PDF-card regressions for partially assessed DNS results."""
from unittest.mock import patch
import pdf_cards as cards
from pdf_helpers import build_styles


def run_checks():
    s = build_styles()
    text = 'Completed probes found no high-risk ports. Coverage is incomplete, so the overall attack surface cannot be confirmed.'

    def capture(data):
        with patch.object(cards, 'build_cat_card', return_value=[]) as builder:
            parts = cards.cat_dns({'dns_infrastructure': data}, s)
        args, kwargs = builder.call_args
        prose = ' '.join(getattr(part, 'text', '') for part in parts)
        return args, kwargs, prose

    for ports in ([], [{'port': 443, 'service': 'HTTPS', 'risk': 'info'}],
                  [{'port': 80, 'service': 'HTTP', 'risk': 'info'},
                   {'port': 443, 'service': 'HTTPS', 'risk': 'info'},
                   {'port': 8443, 'service': 'HTTPS', 'risk': 'info'}]):
        args, kwargs, prose = capture({'partial_coverage': True, 'open_ports': ports})
        assert args[2] == f'{len(ports)} observed open port(s) — partial assessment'
        assert kwargs['fallback'] == text and text in prose
        assert 'Minimal attack surface' not in kwargs['fallback']
        assert 'Only essential services' not in prose
        assert 'significantly reducing the risk' not in prose
    high = {'port': 3389, 'service': 'RDP', 'risk': 'high'}
    args, kwargs, prose = capture({'partial_coverage': True, 'open_ports': [high]})
    assert args[2] == '1 observed open port(s) — partial assessment'
    assert '1 high-risk port(s) exposed' in kwargs['fallback']
    assert 'High-risk ports are exposed' in prose and '3389/RDP' in prose
    args, kwargs, prose = capture({'open_ports': []})
    assert args[2] == '0 open port(s)' and 'Minimal attack surface' in kwargs['fallback']
    assert 'Only essential services' in prose
    print('PARTIAL DNS PDF GREEN: partial-clean and partial-high wording')


if __name__ == '__main__':
    run_checks()
