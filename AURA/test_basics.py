import os
from aura import AURA, ensure_reports_dirs

def test_instantiation_and_dry_run(tmp_path, monkeypatch):
    # instantiate with --dry-run to avoid network calls
    scanner = AURA("http://example.com", dry_run=True, depth=1, delay=0)
    assert scanner.target_url.startswith("http://")
    # run a limited crawl (dry run avoids network)
    scanner.crawl_website(max_depth=1)
    # generate a report and ensure file is created
    ensure_reports_dirs()
    path = scanner.generate_report(filename=f"test_report_{tmp_path.name}.json")
    assert os.path.exists(path)
