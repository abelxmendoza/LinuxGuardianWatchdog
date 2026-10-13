from linuxguardian_ui.reports import ActivityReport, export_saved_scan, export_session


def test_audit_groups_without_claiming_safety():
    report = ActivityReport('Security audit', 'audit', lines=[
        '\x1b[31m[WARN] Firewall status could not be verified\x1b[0m',
        '[ OK ] AppArmor enabled', '[FAIL] A check failed',
        'LG_PROGRESS|phase=audit|pct=50', 'unrecognized diagnostic detail',
    ], exit_code=1, finished=True)
    assert len(report.groups()['Needs attention']) == 2
    assert report.groups()['Passed checks'] == ['[ OK ] AppArmor enabled']
    assert 'nonzero exit code' in report.summary()
    assert 'Network access' in report.summary()
    assert 'unrecognized diagnostic detail' in report.export()
    assert 'LG_PROGRESS|' in report.export()
    assert '\x1b' not in report.export()


def test_session_keeps_previous_runs_and_partial_status():
    first = ActivityReport('Security audit', 'audit', lines=['first'], finished=True, exit_code=0)
    second = ActivityReport('Integrity check', 'integrity', lines=['second'])
    text = export_session([first, second])
    assert 'first' in text and 'second' in text
    assert 'In progress — partial output' in text
    second.finished = True
    assert 'exit status unavailable' in second.export()
    assert export_session([]) == ''


def test_compact_summary_does_not_truncate_export():
    report = ActivityReport('Scan', 'scan', lines=[f'[WARN] warning {i}' for i in range(20)])
    assert '+ 14 more' in report.summary(compact=True)
    assert 'warning 19' in report.export()


def test_saved_reports_include_metadata_and_missing_report(tmp_path):
    log = tmp_path / 'scan.log'
    log.write_text('original output\nlast line\n')
    text = export_saved_scan({'report': str(log), 'rk_report': str(tmp_path / 'missing'), 'clam_rc': 0})
    assert 'original output\nlast line' in text
    assert 'Report unavailable:' in text
    assert '"clam_rc": 0' in text
    assert export_saved_scan(None) == ''


def test_structured_export_includes_beyond_display_limit():
    from linuxguardian_ui.activity import Card, Group, Row
    from linuxguardian_ui.reports import export_card
    card = Card('audit', 'Security audit', rows=[Row('warn', 'Firewall unknown'), Row('warn', 'Passwordless sudo')],
                groups=[Group('all', 'All findings', 'warn', items=[f'item {i}' for i in range(150)])])
    text = export_card(card)
    assert 'item 149' in text
    assert 'Network & remote access' in text
    assert 'Accounts & administrator access' in text
