#!/usr/bin/env python3
import os
import glob
import boto3
import re
from bs4 import BeautifulSoup
from datetime import datetime
from botocore.exceptions import ClientError

def consolidate_html_reports():
    """Consolidate HTML reports from all accounts into a single report with professional styling"""

    try:
        s3 = boto3.client('s3')
    except Exception as e:
        print(f"Error creating S3 client: {str(e)}")
        raise

    bucket = os.environ.get('BUCKET_REPORT')
    if not bucket:
        print("Error: BUCKET_REPORT environment variable is not set")
        raise ValueError("BUCKET_REPORT environment variable is required")

    all_findings = []
    account_ids = set()
    service_stats = {'bedrock': {'passed': 0, 'failed': 0}, 'sagemaker': {'passed': 0, 'failed': 0}, 'agentcore': {'passed': 0, 'failed': 0}}

    # Process HTML files from each account directory (exclude consolidated-reports)
    for account_dir in glob.glob('/tmp/account-files/*/'):
        account_id = os.path.basename(account_dir.rstrip('/'))
        if account_id == 'consolidated-reports':
            continue

        html_files = glob.glob(os.path.join(account_dir, '**/security_assessment_*.html'), recursive=True)

        if html_files:
            print(f"Processing HTML files for account {account_id}")
            account_ids.add(account_id)

            try:
                with open(html_files[0], 'r') as f:
                    soup = BeautifulSoup(f.read(), 'html.parser')
            except IOError as e:
                print(f"Error reading HTML file for account {account_id}: {str(e)}")
                continue
            except Exception as e:
                print(f"Error parsing HTML for account {account_id}: {str(e)}")
                continue

            tbody = soup.find('tbody')
            if tbody:
                rows = tbody.find_all('tr')
                for row in rows:
                    cells = row.find_all('td')
                    if len(cells) >= 7:
                        finding = {
                            'account_id': account_id,
                            'finding': cells[1].get_text(strip=True) if len(cells) > 1 else '',
                            'details': cells[2].get_text(strip=True) if len(cells) > 2 else '',
                            'resolution': cells[3].get_text(strip=True) if len(cells) > 3 else '',
                            'reference': '',
                            'severity': cells[5].get_text(strip=True) if len(cells) > 5 else '',
                            'status': cells[6].get_text(strip=True) if len(cells) > 6 else ''
                        }
                        # Extract reference URLs
                        ref_cell = cells[4] if len(cells) > 4 else None
                        if ref_cell:
                            links = ref_cell.find_all('a')
                            if links:
                                finding['reference'] = [a.get('href', '') for a in links]
                            else:
                                finding['reference'] = [ref_cell.get_text(strip=True)]

                        all_findings.append(finding)

                        # Categorize by service
                        finding_name = finding['finding'].lower()
                        status = finding['status'].lower()
                        if 'bedrock' in finding_name or 'guardrail' in finding_name:
                            service = 'bedrock'
                        elif 'sagemaker' in finding_name or 'domain' in finding_name:
                            service = 'sagemaker'
                        elif 'agentcore' in finding_name or 'runtime' in finding_name:
                            service = 'agentcore'
                        else:
                            service = 'bedrock'  # default

                        if status == 'passed':
                            service_stats[service]['passed'] += 1
                        elif status == 'failed':
                            service_stats[service]['failed'] += 1

    if all_findings:
        # Calculate metrics
        total_findings = len(all_findings)
        high_count = sum(1 for f in all_findings if f['severity'].lower() == 'high')
        medium_count = sum(1 for f in all_findings if f['severity'].lower() == 'medium')
        low_count = sum(1 for f in all_findings if f['severity'].lower() == 'low')
        passed_count = sum(1 for f in all_findings if f['status'].lower() == 'passed')

        # Get high priority recommendations
        high_priority = [f for f in all_findings if f['severity'].lower() == 'high' and f['status'].lower() == 'failed'][:3]
        medium_priority = [f for f in all_findings if f['severity'].lower() == 'medium' and f['status'].lower() == 'failed'][:2]

        recommendations_html = ""
        for f in high_priority:
            recommendations_html += f'<li><span class="priority-indicator high"></span><span>{f["resolution"] or f["finding"]}</span></li>'
        for f in medium_priority:
            recommendations_html += f'<li><span class="priority-indicator medium"></span><span>{f["resolution"] or f["finding"]}</span></li>'
        if not recommendations_html:
            recommendations_html = '<li><span class="priority-indicator"></span><span>No critical recommendations at this time</span></li>'

        # Build account options
        account_options = ''.join([f'<option value="{acc}">{acc}</option>' for acc in sorted(account_ids)])

        # Build table rows
        rows_html = []
        for f in all_findings:
            severity = f['severity'].lower()
            severity_class = severity if severity in ['high', 'medium', 'low'] else 'na'
            status = f['status'].lower()
            status_class = 'passed' if status == 'passed' else 'failed'

            # Build reference buttons
            refs = f.get('reference', [])
            if isinstance(refs, str):
                refs = [refs]
            ref_html = ''.join([f'<a href="{ref}" target="_blank" class="reference-btn" title="{ref}">View Docs</a>' for ref in refs if ref and ref.strip()])
            if not ref_html:
                ref_html = '<span style="color: var(--text-secondary);">-</span>'

            row = f'''<tr>
                <td>{f['account_id']}</td>
                <td>{f['finding']}</td>
                <td class="finding-details">{f['details']}</td>
                <td class="resolution-text">{f['resolution']}</td>
                <td class="reference-cell">{ref_html}</td>
                <td><span class="severity-badge {severity_class}">{f['severity']}</span></td>
                <td><span class="status-badge {status_class}">{f['status']}</span></td>
            </tr>'''
            rows_html.append(row)

        timestamp_display = datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')

        html_template = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Multi-Account ReSCO AI/ML Security Assessment Report</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        :root {{
            --primary: #111827;
            --accent: #6366f1;
            --accent-light: #eef2ff;
            --bg-page: #ffffff;
            --bg-card: #ffffff;
            --bg-subtle: #f9fafb;
            --severity-high: #ef4444;
            --severity-medium: #f59e0b;
            --severity-low: #6366f1;
            --severity-na: #9ca3af;
            --status-passed: #10b981;
            --status-failed: #ef4444;
            --border-color: #d1d5db;
            --border-strong: #9ca3af;
            --text-primary: #111827;
            --text-secondary: #6b7280;
            --card-shadow: 0 1px 3px rgba(0,0,0,0.1), 0 1px 2px rgba(0,0,0,0.06);
        }}
        [data-theme="dark"] {{
            --primary: #f9fafb;
            --accent: #818cf8;
            --accent-light: rgba(129, 140, 248, 0.15);
            --bg-page: #0f172a;
            --bg-card: #1e293b;
            --bg-subtle: #334155;
            --severity-high: #f87171;
            --severity-medium: #fbbf24;
            --severity-low: #818cf8;
            --severity-na: #64748b;
            --status-passed: #4ade80;
            --status-failed: #f87171;
            --border-color: #475569;
            --border-strong: #64748b;
            --text-primary: #f1f5f9;
            --text-secondary: #94a3b8;
            --card-shadow: 0 1px 3px rgba(0,0,0,0.3), 0 1px 2px rgba(0,0,0,0.2);
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: var(--bg-page); color: var(--text-primary); line-height: 1.6; }}
        .theme-toggle {{ display: flex; align-items: center; gap: 8px; padding: 8px 16px; background: var(--bg-subtle); border: 2px solid var(--border-color); border-radius: 50px; cursor: pointer; font-size: 13px; font-weight: 600; color: var(--text-primary); transition: all 0.2s ease; }}
        .theme-toggle:hover {{ border-color: var(--accent); background: var(--accent-light); }}
        .theme-toggle-icon {{ width: 20px; height: 20px; display: flex; align-items: center; justify-content: center; }}
        .theme-toggle .sun-icon {{ display: none; }}
        .theme-toggle .moon-icon {{ display: block; }}
        [data-theme="dark"] .theme-toggle .sun-icon {{ display: block; }}
        [data-theme="dark"] .theme-toggle .moon-icon {{ display: none; }}
        .header {{ background: var(--bg-card); color: var(--primary); padding: 32px 40px; display: flex; align-items: center; justify-content: space-between; border-bottom: 2px solid var(--border-color); }}
        .header h1 {{ font-size: 26px; font-weight: 700; letter-spacing: -0.5px; }}
        .header-right {{ display: flex; align-items: center; gap: 20px; }}
        .header-meta {{ text-align: right; font-size: 14px; color: var(--text-secondary); }}
        .container {{ max-width: 1600px; margin: 0 auto; padding: 24px; }}
        .exec-summary {{ background: var(--bg-card); border-radius: 16px; margin-bottom: 32px; border: 2px solid var(--border-color); overflow: hidden; box-shadow: var(--card-shadow); }}
        .exec-summary-header {{ background: var(--bg-subtle); padding: 20px 28px; border-bottom: 2px solid var(--border-color); }}
        .exec-summary-header h2 {{ font-size: 16px; font-weight: 600; color: var(--text-primary); text-transform: uppercase; letter-spacing: 1px; }}
        .metrics-grid {{ display: grid; grid-template-columns: repeat(5, 1fr); border-bottom: 2px solid var(--border-color); }}
        .metric-card {{ padding: 28px; text-align: center; border-right: 2px solid var(--border-color); background: var(--bg-card); transition: background-color 0.15s; }}
        .metric-card:last-child {{ border-right: none; }}
        .metric-card:hover {{ background: var(--bg-subtle); }}
        .metric-value {{ font-size: 42px; font-weight: 800; line-height: 1; margin-bottom: 8px; letter-spacing: -1px; }}
        .metric-label {{ font-size: 12px; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 1px; font-weight: 500; }}
        .metric-card.total .metric-value {{ color: var(--primary); }}
        .metric-card.high .metric-value {{ color: var(--severity-high); }}
        .metric-card.medium .metric-value {{ color: var(--severity-medium); }}
        .metric-card.low .metric-value {{ color: var(--severity-low); }}
        .metric-card.passed .metric-value {{ color: var(--status-passed); }}
        .breakdown-section {{ padding: 28px; display: grid; grid-template-columns: 1fr 1fr; gap: 28px; }}
        .breakdown-card {{ background: var(--bg-subtle); border-radius: 12px; padding: 24px; border: 2px solid var(--border-color); }}
        .breakdown-card h3 {{ font-size: 12px; font-weight: 700; color: var(--text-primary); margin-bottom: 20px; text-transform: uppercase; letter-spacing: 1px; }}
        .service-row {{ display: flex; align-items: center; justify-content: space-between; padding: 14px 0; border-bottom: 1px solid var(--border-color); }}
        .service-row:last-child {{ border-bottom: none; padding-bottom: 0; }}
        .service-name {{ font-weight: 600; font-size: 15px; display: flex; align-items: center; gap: 12px; }}
        .service-icon {{ width: 32px; height: 32px; background: var(--primary); border-radius: 8px; display: flex; align-items: center; justify-content: center; color: white; font-size: 13px; font-weight: 700; }}
        [data-theme="dark"] .service-icon {{ background: var(--accent); color: #0f172a; }}
        .service-stats {{ display: flex; gap: 10px; }}
        .stat-badge {{ padding: 6px 14px; border-radius: 8px; font-size: 13px; font-weight: 600; }}
        .stat-badge.failed {{ background: #fef2f2; color: var(--severity-high); }}
        .stat-badge.passed {{ background: #ecfdf5; color: var(--status-passed); }}
        .recommendations-list {{ list-style: none; }}
        .recommendations-list li {{ display: flex; align-items: flex-start; gap: 14px; padding: 14px 0; border-bottom: 1px solid var(--border-color); font-size: 14px; line-height: 1.5; }}
        .recommendations-list li:last-child {{ border-bottom: none; padding-bottom: 0; }}
        .priority-indicator {{ width: 10px; height: 10px; border-radius: 50%; margin-top: 5px; flex-shrink: 0; }}
        .priority-indicator.high {{ background: var(--severity-high); }}
        .priority-indicator.medium {{ background: var(--severity-medium); }}
        .findings-section {{ background: var(--bg-card); border-radius: 16px; border: 2px solid var(--border-color); overflow: hidden; box-shadow: var(--card-shadow); }}
        .findings-header {{ padding: 20px 28px; background: var(--bg-subtle); border-bottom: 2px solid var(--border-color); display: flex; justify-content: space-between; align-items: center; }}
        .findings-header h2 {{ font-size: 16px; font-weight: 700; color: var(--text-primary); text-transform: uppercase; letter-spacing: 1px; }}
        .search-box {{ position: relative; }}
        .search-box input {{ padding: 12px 16px 12px 44px; border: 1px solid var(--border-color); border-radius: 10px; width: 320px; font-size: 14px; background: var(--bg-card); color: var(--text-primary); transition: all 0.2s; }}
        .search-box input:focus {{ outline: none; border-color: var(--accent); box-shadow: 0 0 0 3px var(--accent-light); }}
        .search-box::before {{ content: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='18' height='18' fill='%239ca3af' viewBox='0 0 16 16'%3E%3Cpath d='M11.742 10.344a6.5 6.5 0 1 0-1.397 1.398h-.001c.03.04.062.078.098.115l3.85 3.85a1 1 0 0 0 1.415-1.414l-3.85-3.85a1.007 1.007 0 0 0-.115-.1zM12 6.5a5.5 5.5 0 1 1-11 0 5.5 5.5 0 0 1 11 0z'/%3E%3C/svg%3E"); position: absolute; left: 16px; top: 50%; transform: translateY(-50%); }}
        .findings-table-container {{ overflow-x: auto; }}
        .findings-table {{ width: 100%; border-collapse: collapse; font-size: 13px; table-layout: fixed; }}
        .findings-table thead {{ background: var(--bg-subtle); }}
        .findings-table th {{ padding: 12px 10px; text-align: left; font-weight: 700; font-size: 11px; color: var(--text-primary); text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 3px solid var(--border-strong); background: var(--bg-subtle); }}
        .findings-table th:nth-child(1) {{ width: 10%; }} /* Account ID */
        .findings-table th:nth-child(2) {{ width: 15%; }} /* Finding */
        .findings-table th:nth-child(3) {{ width: 20%; }} /* Finding Details */
        .findings-table th:nth-child(4) {{ width: 22%; }} /* Resolution */
        .findings-table th:nth-child(5) {{ width: 8%; }} /* Reference */
        .findings-table th:nth-child(6) {{ width: 10%; }} /* Severity */
        .findings-table th:nth-child(7) {{ width: 10%; }} /* Status */
        .findings-table th .filter-input, .findings-table th .filter-select {{ display: block; width: 100%; margin-top: 8px; padding: 6px 8px; border: 1px solid var(--border-color); border-radius: 6px; font-size: 12px; font-weight: normal; text-transform: none; letter-spacing: normal; background: var(--bg-card); color: var(--text-primary); }}
        .findings-table th .filter-input:focus, .findings-table th .filter-select:focus {{ outline: none; border-color: var(--accent); }}
        .findings-table th .filter-select {{ cursor: pointer; appearance: none; background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' fill='%236b7280' viewBox='0 0 16 16'%3E%3Cpath d='M7.247 11.14L2.451 5.658C1.885 5.013 2.345 4 3.204 4h9.592a1 1 0 0 1 .753 1.659l-4.796 5.48a1 1 0 0 1-1.506 0z'/%3E%3C/svg%3E"); background-repeat: no-repeat; background-position: right 8px center; padding-right: 28px; }}
        [data-theme="dark"] .findings-table th .filter-select {{ background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' fill='%2394a3b8' viewBox='0 0 16 16'%3E%3Cpath d='M7.247 11.14L2.451 5.658C1.885 5.013 2.345 4 3.204 4h9.592a1 1 0 0 1 .753 1.659l-4.796 5.48a1 1 0 0 1-1.506 0z'/%3E%3C/svg%3E"); }}
        .findings-table th.no-filter {{ vertical-align: top; }}
        .findings-table tbody tr {{ transition: background-color 0.15s; background: var(--bg-card); }}
        .findings-table tbody tr:hover {{ background: var(--bg-subtle); }}
        .findings-table td {{ padding: 12px 10px; border-bottom: 1px solid var(--border-color); vertical-align: top; color: var(--text-primary); word-wrap: break-word; overflow-wrap: break-word; }}
        .findings-table td:first-child {{ font-family: 'SF Mono', 'Monaco', monospace; font-size: 11px; color: var(--text-secondary); }}
        .severity-badge {{ display: inline-flex; align-items: center; padding: 4px 8px; border-radius: 6px; font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.3px; }}
        .severity-badge.high {{ background: #fef2f2; color: var(--severity-high); }}
        .severity-badge.medium {{ background: #fffbeb; color: #b45309; }}
        .severity-badge.low {{ background: var(--accent-light); color: var(--severity-low); }}
        .severity-badge.na {{ background: #f3f4f6; color: var(--severity-na); }}
        .status-badge {{ display: inline-flex; align-items: center; gap: 4px; padding: 4px 8px; border-radius: 12px; font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.3px; }}
        .status-badge.passed {{ background: #ecfdf5; color: var(--status-passed); }}
        .status-badge.failed {{ background: #fef2f2; color: var(--status-failed); }}
        .status-badge::before {{ content: ''; width: 6px; height: 6px; border-radius: 50%; background: currentColor; }}
        .reference-btn {{ display: inline-flex; align-items: center; gap: 4px; padding: 4px 8px; background: var(--accent-light); color: var(--accent); text-decoration: none; border-radius: 6px; font-size: 11px; font-weight: 600; border: 1px solid var(--border-color); transition: all 0.15s ease; margin: 2px 0; }}
        .reference-btn:hover {{ background: var(--accent); color: white; border-color: var(--accent); }}
        .reference-btn::after {{ content: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' fill='%236366f1' viewBox='0 0 16 16'%3E%3Cpath fill-rule='evenodd' d='M8.636 3.5a.5.5 0 0 0-.5-.5H1.5A1.5 1.5 0 0 0 0 4.5v10A1.5 1.5 0 0 0 1.5 16h10a1.5 1.5 0 0 0 1.5-1.5V7.864a.5.5 0 0 0-1 0V14.5a.5.5 0 0 1-.5.5h-10a.5.5 0 0 1-.5-.5v-10a.5.5 0 0 1 .5-.5h6.636a.5.5 0 0 0 .5-.5z'/%3E%3Cpath fill-rule='evenodd' d='M16 .5a.5.5 0 0 0-.5-.5h-5a.5.5 0 0 0 0 1h3.793L6.146 9.146a.5.5 0 1 0 .708.708L15 1.707V5.5a.5.5 0 0 0 1 0v-5z'/%3E%3C/svg%3E"); transition: all 0.15s; }}
        [data-theme="dark"] .reference-btn::after {{ content: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' fill='%23818cf8' viewBox='0 0 16 16'%3E%3Cpath fill-rule='evenodd' d='M8.636 3.5a.5.5 0 0 0-.5-.5H1.5A1.5 1.5 0 0 0 0 4.5v10A1.5 1.5 0 0 0 1.5 16h10a1.5 1.5 0 0 0 1.5-1.5V7.864a.5.5 0 0 0-1 0V14.5a.5.5 0 0 1-.5.5h-10a.5.5 0 0 1-.5-.5v-10a.5.5 0 0 1 .5-.5h6.636a.5.5 0 0 0 .5-.5z'/%3E%3Cpath fill-rule='evenodd' d='M16 .5a.5.5 0 0 0-.5-.5h-5a.5.5 0 0 0 0 1h3.793L6.146 9.146a.5.5 0 1 0 .708.708L15 1.707V5.5a.5.5 0 0 0 1 0v-5z'/%3E%3C/svg%3E"); }}
        .reference-btn:hover::after {{ content: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' fill='white' viewBox='0 0 16 16'%3E%3Cpath fill-rule='evenodd' d='M8.636 3.5a.5.5 0 0 0-.5-.5H1.5A1.5 1.5 0 0 0 0 4.5v10A1.5 1.5 0 0 0 1.5 16h10a1.5 1.5 0 0 0 1.5-1.5V7.864a.5.5 0 0 0-1 0V14.5a.5.5 0 0 1-.5.5h-10a.5.5 0 0 1-.5-.5v-10a.5.5 0 0 1 .5-.5h6.636a.5.5 0 0 0 .5-.5z'/%3E%3Cpath fill-rule='evenodd' d='M16 .5a.5.5 0 0 0-.5-.5h-5a.5.5 0 0 0 0 1h3.793L6.146 9.146a.5.5 0 1 0 .708.708L15 1.707V5.5a.5.5 0 0 0 1 0v-5z'/%3E%3C/svg%3E"); }}
        .reference-cell {{ display: flex; flex-direction: column; gap: 4px; }}
        .finding-details {{ color: var(--text-secondary); line-height: 1.5; font-size: 12px; }}
        .resolution-text {{ color: var(--text-secondary); font-size: 12px; line-height: 1.5; }}
        .report-footer {{ text-align: center; padding: 32px; color: var(--text-secondary); font-size: 13px; }}
        .report-footer a {{ color: var(--accent); text-decoration: none; font-weight: 500; }}
        @media (max-width: 1200px) {{ .metrics-grid {{ grid-template-columns: repeat(3, 1fr); }} .breakdown-section {{ grid-template-columns: 1fr; }} }}
        @media (max-width: 768px) {{ .header {{ flex-direction: column; gap: 16px; text-align: center; }} .metrics-grid {{ grid-template-columns: repeat(2, 1fr); }} .metric-card {{ border-right: none; border-bottom: 1px solid var(--border-color); }} .findings-header {{ flex-direction: column; gap: 16px; }} .search-box input {{ width: 100%; }} }}
    </style>
</head>
<body>
    <header class="header">
        <h1>Multi-Account ReSCO AI/ML Security Assessment</h1>
        <div class="header-right">
            <div class="header-meta">
                <div>{num_accounts} Accounts</div>
                <div>{timestamp}</div>
            </div>
            <button class="theme-toggle" id="themeToggle" aria-label="Toggle dark mode">
                <span class="theme-toggle-icon">
                    <svg class="moon-icon" xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 16 16"><path d="M6 .278a.768.768 0 0 1 .08.858 7.208 7.208 0 0 0-.878 3.46c0 4.021 3.278 7.277 7.318 7.277.527 0 1.04-.055 1.533-.16a.787.787 0 0 1 .81.316.733.733 0 0 1-.031.893A8.349 8.349 0 0 1 8.344 16C3.734 16 0 12.286 0 7.71 0 4.266 2.114 1.312 5.124.06A.752.752 0 0 1 6 .278z"/></svg>
                    <svg class="sun-icon" xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 16 16"><path d="M8 11a3 3 0 1 1 0-6 3 3 0 0 1 0 6zm0 1a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM8 0a.5.5 0 0 1 .5.5v2a.5.5 0 0 1-1 0v-2A.5.5 0 0 1 8 0zm0 13a.5.5 0 0 1 .5.5v2a.5.5 0 0 1-1 0v-2A.5.5 0 0 1 8 13zm8-5a.5.5 0 0 1-.5.5h-2a.5.5 0 0 1 0-1h2a.5.5 0 0 1 .5.5zM3 8a.5.5 0 0 1-.5.5h-2a.5.5 0 0 1 0-1h2A.5.5 0 0 1 3 8zm10.657-5.657a.5.5 0 0 1 0 .707l-1.414 1.415a.5.5 0 1 1-.707-.708l1.414-1.414a.5.5 0 0 1 .707 0zm-9.193 9.193a.5.5 0 0 1 0 .707L3.05 13.657a.5.5 0 0 1-.707-.707l1.414-1.414a.5.5 0 0 1 .707 0zm9.193 2.121a.5.5 0 0 1-.707 0l-1.414-1.414a.5.5 0 0 1 .707-.707l1.414 1.414a.5.5 0 0 1 0 .707zM4.464 4.465a.5.5 0 0 1-.707 0L2.343 3.05a.5.5 0 1 1 .707-.707l1.414 1.414a.5.5 0 0 1 0 .708z"/></svg>
                </span>
                <span class="theme-label">Dark</span>
            </button>
        </div>
    </header>
    <main class="container">
        <section class="exec-summary">
            <div class="exec-summary-header"><h2>Executive Summary</h2></div>
            <div class="metrics-grid">
                <div class="metric-card total"><div class="metric-value">{total_findings}</div><div class="metric-label">Total Findings</div></div>
                <div class="metric-card high"><div class="metric-value">{high_count}</div><div class="metric-label">High Severity</div></div>
                <div class="metric-card medium"><div class="metric-value">{medium_count}</div><div class="metric-label">Medium Severity</div></div>
                <div class="metric-card low"><div class="metric-value">{low_count}</div><div class="metric-label">Low Severity</div></div>
                <div class="metric-card passed"><div class="metric-value">{passed_count}</div><div class="metric-label">Passed Checks</div></div>
            </div>
            <div class="breakdown-section">
                <div class="breakdown-card">
                    <h3>Findings by Service</h3>
                    <div class="service-row"><span class="service-name"><span class="service-icon">B</span>Amazon Bedrock</span><div class="service-stats"><span class="stat-badge failed">{bedrock_failed} Failed</span><span class="stat-badge passed">{bedrock_passed} Passed</span></div></div>
                    <div class="service-row"><span class="service-name"><span class="service-icon">S</span>Amazon SageMaker</span><div class="service-stats"><span class="stat-badge failed">{sagemaker_failed} Failed</span><span class="stat-badge passed">{sagemaker_passed} Passed</span></div></div>
                    <div class="service-row"><span class="service-name"><span class="service-icon">A</span>AgentCore</span><div class="service-stats"><span class="stat-badge failed">{agentcore_failed} Failed</span><span class="stat-badge passed">{agentcore_passed} Passed</span></div></div>
                </div>
                <div class="breakdown-card"><h3>Priority Recommendations</h3><ul class="recommendations-list">{recommendations}</ul></div>
            </div>
        </section>
        <section class="findings-section">
            <div class="findings-header"><h2>Detailed Findings</h2><div class="search-box"><input type="text" id="searchInput" placeholder="Search across all columns..."></div></div>
            <div class="findings-table-container">
                <table class="findings-table" id="findingsTable">
                    <thead><tr>
                        <th>Account ID<select class="filter-select" data-column="0"><option value="">All Accounts</option>{account_options}</select></th>
                        <th>Finding<input type="text" class="filter-input" placeholder="Search findings..." data-column="1"></th>
                        <th class="no-filter">Finding Details</th>
                        <th class="no-filter">Resolution</th>
                        <th class="no-filter">Reference</th>
                        <th>Severity<select class="filter-select" data-column="5"><option value="">All Severities</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="n/a">N/A</option></select></th>
                        <th>Status<select class="filter-select" data-column="6"><option value="">All Statuses</option><option value="failed">Failed</option><option value="passed">Passed</option></select></th>
                    </tr></thead>
                    <tbody>{rows}</tbody>
                </table>
            </div>
        </section>
        <footer class="report-footer"><p>ReSCO AI/ML Security Assessment | <a href="https://github.com/aws-samples/sample-resco-aiml-assessment">GitHub Repository</a></p></footer>
    </main>
    <script>
        document.addEventListener('DOMContentLoaded', function() {{
            const themeToggle = document.getElementById('themeToggle');
            const themeLabel = themeToggle.querySelector('.theme-label');
            const html = document.documentElement;
            const savedTheme = localStorage.getItem('theme') || 'light';
            if (savedTheme === 'dark') {{ html.setAttribute('data-theme', 'dark'); themeLabel.textContent = 'Light'; }}
            themeToggle.addEventListener('click', function() {{
                const currentTheme = html.getAttribute('data-theme');
                if (currentTheme === 'dark') {{ html.removeAttribute('data-theme'); localStorage.setItem('theme', 'light'); themeLabel.textContent = 'Dark'; }}
                else {{ html.setAttribute('data-theme', 'dark'); localStorage.setItem('theme', 'dark'); themeLabel.textContent = 'Light'; }}
            }});
            const table = document.getElementById('findingsTable');
            const searchInput = document.getElementById('searchInput');
            const textFilters = document.querySelectorAll('.filter-input');
            const selectFilters = document.querySelectorAll('.filter-select');
            function applyFilters() {{
                const searchText = searchInput.value.toLowerCase();
                const rows = table.querySelectorAll('tbody tr');
                rows.forEach(row => {{
                    const cells = row.querySelectorAll('td');
                    const rowText = row.textContent.toLowerCase();
                    let shouldShow = true;
                    if (searchText && !rowText.includes(searchText)) shouldShow = false;
                    const accountFilter = document.querySelector('.filter-select[data-column="0"]').value.toLowerCase();
                    if (accountFilter && cells[0] && !cells[0].textContent.toLowerCase().includes(accountFilter)) shouldShow = false;
                    const findingFilter = document.querySelector('.filter-input[data-column="1"]').value.toLowerCase();
                    if (findingFilter && cells[1] && !cells[1].textContent.toLowerCase().includes(findingFilter)) shouldShow = false;
                    const severityFilter = document.querySelector('.filter-select[data-column="5"]').value.toLowerCase();
                    if (severityFilter && cells[5] && !cells[5].textContent.toLowerCase().includes(severityFilter)) shouldShow = false;
                    const statusFilter = document.querySelector('.filter-select[data-column="6"]').value.toLowerCase();
                    if (statusFilter && cells[6] && !cells[6].textContent.toLowerCase().includes(statusFilter)) shouldShow = false;
                    row.style.display = shouldShow ? '' : 'none';
                }});
            }}
            searchInput.addEventListener('input', applyFilters);
            textFilters.forEach(filter => filter.addEventListener('input', applyFilters));
            selectFilters.forEach(filter => filter.addEventListener('change', applyFilters));
        }});
    </script>
</body>
</html>'''

        consolidated_html = html_template.format(
            timestamp=timestamp_display,
            num_accounts=len(account_ids),
            total_findings=total_findings,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            passed_count=passed_count,
            bedrock_failed=service_stats['bedrock']['failed'],
            bedrock_passed=service_stats['bedrock']['passed'],
            sagemaker_failed=service_stats['sagemaker']['failed'],
            sagemaker_passed=service_stats['sagemaker']['passed'],
            agentcore_failed=service_stats['agentcore']['failed'],
            agentcore_passed=service_stats['agentcore']['passed'],
            recommendations=recommendations_html,
            account_options=account_options,
            rows='\n'.join(rows_html)
        )

        timestamp_file = datetime.now().strftime('%Y%m%d_%H%M%S')
        s3_key = f'consolidated-reports/multi_account_report_{timestamp_file}.html'

        try:
            s3.put_object(
                Bucket=bucket,
                Key=s3_key,
                Body=consolidated_html,
                ContentType='text/html'
            )
            print(f'Consolidated report saved to s3://{bucket}/{s3_key}')
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'NoSuchBucket':
                print(f"Error: Bucket '{bucket}' does not exist")
            elif error_code == 'AccessDenied':
                print(f"Error: Access denied to bucket '{bucket}'")
            else:
                print(f"Error uploading to S3: {str(e)}")
            raise
        except Exception as e:
            print(f"Unexpected error uploading consolidated report: {str(e)}")
            raise
    else:
        print('No HTML reports found for consolidation')
        for account_dir in glob.glob('/tmp/account-files/*/'):
            account_id = os.path.basename(account_dir.rstrip('/'))
            all_files = glob.glob(os.path.join(account_dir, '**/*'), recursive=True)
            print(f"Account {account_id} files: {all_files}")

if __name__ == '__main__':
    consolidate_html_reports()