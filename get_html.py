import json
import datetime

def generate_html_report(scan_data, eval_data, violations_data, sbom_data=None, output_filename="airs_model_scan_report.html"):
    # --- 1. PRISMA METADATA EXTRACTION ---
    scan_uuid = str(scan_data.get("uuid", "N/A"))
    raw_uri = str(scan_data.get("model_uri", "N/A"))
    model_name = "/".join(raw_uri.split('/')[-2:]) if "/" in raw_uri else raw_uri
    sec_group = str(scan_data.get("security_group_name", "N/A"))
    eval_outcome = str(scan_data.get("eval_outcome", "UNKNOWN"))
    scanner_version = str(scan_data.get("scanner_version", "N/A"))

    # EXACT RAW VALUE FROM API AS REQUESTED
    source_type_raw = scan_data.get("source_type", "N/A")
    scan_type_display = str(source_type_raw)

    try:
        dt = datetime.datetime.strptime(scan_data.get("created_at"), "%Y-%m-%dT%H:%M:%S.%fZ")
        executed_at = dt.strftime("%Y-%m-%d %H:%M:%S+00:00")
    except:
        executed_at = str(scan_data.get("created_at", "N/A"))

    rules_passed = scan_data.get("eval_summary", {}).get("rules_passed", 0)
    rules_failed = scan_data.get("eval_summary", {}).get("rules_failed", 0)
    total_rules = scan_data.get("eval_summary", {}).get("total_rules", 0)

    # --- 2. SECURITY VIOLATIONS & REMEDIATIONS ---
    unique_remediations = {}
    v_list = violations_data.get("violations", []) if isinstance(violations_data, dict) else []
    for v in v_list:
        rule_name = str(v.get("rule_name", "Unknown Rule"))
        if rule_name not in unique_remediations:
            unique_remediations[rule_name] = {
                "description": v.get("rule_description"),
                "remediation_steps": v.get("remediation", {}).get("steps", []) if isinstance(v.get("remediation"), dict) else [],
                "url": v.get("remediation", {}).get("url", "#") if isinstance(v.get("remediation"), dict) else "#",
                "state": v.get("rule_instance_state", "UNKNOWN")
            }

    remediations_html = ""
    for idx, (rule_name, details) in enumerate(unique_remediations.items(), 1):
        steps_html = "".join([f"<li>{step}</li>" for step in details['remediation_steps']])
        remediations_html += f"""
        <div class="remediation-card">
            <h4>{idx}. {rule_name} <span class="badge badge-state">{details['state']}</span></h4>
            <p><strong>Description:</strong> {details['description']}</p>
            <p><strong>Remediation Steps:</strong></p>
            <ul>{steps_html}</ul>
            <p><a href="{details['url']}" target="_blank">View Documentation Resource</a></p>
        </div>
        """

    violations_html = ""
    for idx, v in enumerate(v_list, 1):
        file_info = f"<p><strong>File:</strong> <code>{v.get('file')}</code></p>" if v.get("file") else ""
        threat_info = f"<p><strong>Threat:</strong> {v.get('threat')}</p>" if v.get("threat") else ""
        
        # Capture deep-dive external URLs dynamically if present
        insights_url = v.get("insights_url")
        threat_kb_url = v.get("threat_kb_url")
        
        links_html = ""
        if insights_url or threat_kb_url:
            links_html += '<div style="margin-top: 12px; display: flex; gap: 15px; border-top: 1px dashed #cbd5e1; padding-top: 10px;">'
            if insights_url:
                links_html += f'<a href="{insights_url}" target="_blank" style="font-size: 13px; color: var(--prisma-teal); font-weight: bold; text-decoration: none;">🔍 View Runtime Insights</a>'
            if threat_kb_url:
                links_html += f'<a href="{threat_kb_url}" target="_blank" style="font-size: 13px; color: var(--aibom-purple); font-weight: bold; text-decoration: none;">🛡️ Threat Intel KB</a>'
            links_html += '</div>'

        violations_html += f"""
        <div class="violation-card">
            <h5>Violation #{idx}: {v.get('rule_name')}</h5>
            <p>{v.get('description')}</p>
            {file_info}
            {threat_info}
            {links_html}
        </div>
        """

    eval_rows_html = ""
    e_list = eval_data.get("evaluations", []) if isinstance(eval_data, dict) else []
    for e in e_list:
        res = str(e.get("result", ""))
        badge_class = "badge-passed" if res == "PASSED" else "badge-failed"
        eval_rows_html += f"""<tr><td>{e.get('rule_name')}</td><td>{e.get('rule_description')}</td><td><span class="badge {badge_class}">{res}</span></td></tr>"""

    outcome_color = "#d9534f" if eval_outcome in ["BLOCKED", "FAILED"] else "#5cb85c"

    # --- 3. ENHANCED SBOM, SCORECARD & CHECKLIST ---
    sbom_html = ""
    checklist_html = ""
    
    if sbom_data and isinstance(sbom_data, dict):
        ml_model = sbom_data.get("components", [{}])[0]
        meta_comp = sbom_data.get("metadata", {}).get("component", {})
        model_card = ml_model.get("modelCard", {})
        params = model_card.get("modelParameters", {})
        cons = model_card.get("considerations", {})
        
        version = str(meta_comp.get("version", "N/A"))
        purl = str(meta_comp.get("purl", "N/A"))
        
        licenses_list = meta_comp.get("licenses", [{}])
        licenses = "Unknown"
        if licenses_list and isinstance(licenses_list, list) and isinstance(licenses_list[0], dict):
            licenses = str(licenses_list[0].get("license", {}).get("id", "Unknown"))
        
        arch, vocab, tok = "N/A", "N/A", "N/A"
        for p in ml_model.get("properties", []):
            if p.get("name") == "Architecture": arch = str(p.get("value", "N/A"))
            if p.get("name") == "vocabSize": vocab = str(p.get("value", "N/A"))
            if p.get("name") == "tokenizerClass": tok = str(p.get("value", "N/A"))
            
        downloads = "N/A"
        metrics = model_card.get("quantitativeAnalysis", {}).get("performanceMetrics", [])
        if metrics and isinstance(metrics, list) and isinstance(metrics[0], dict):
            downloads = str(metrics[0].get("value", "N/A"))
            
        model_id = str(ml_model.get('name', 'N/A'))
        serial_number = str(sbom_data.get("serialNumber", "N/A"))
        task = str(params.get("task", "N/A"))
        supplier = str(meta_comp.get("supplier", {}).get("name", "N/A"))
        approach = str(params.get("approach", "N/A"))
        safety = str(cons.get("safetyRiskAssessment", "N/A"))
        desc = str(meta_comp.get("description", "N/A"))
        timestamp = str(sbom_data.get("metadata", {}).get("timestamp", "N/A"))
        
        datasets = str(params.get("datasets", "N/A"))
        ethical = str(cons.get("ethicalConsiderations", "N/A"))
        energy = str(cons.get("energyConsumption", "N/A"))
        hyper = str(params.get("hyperparameters", "N/A"))
        tech_limit = str(cons.get("technicalLimitations", "N/A"))
        intended = str(cons.get("intendedUse", "N/A"))
        download_loc = f"https://huggingface.co/{model_id}" if model_id != "N/A" else "N/A"

        fields_to_check = [
            {"name": "bomFormat", "value": str(sbom_data.get("bomFormat", "N/A")), "tier": "Critical", "category": "Required Fields"},
            {"name": "specVersion", "value": str(sbom_data.get("specVersion", "N/A")), "tier": "Critical", "category": "Required Fields"},
            {"name": "serialNumber", "value": serial_number, "tier": "Critical", "category": "Required Fields"},
            {"name": "version", "value": version, "tier": "Critical", "category": "Required Fields"},
            {"name": "Timestamp", "value": timestamp, "tier": "Supplementary", "category": "Metadata"},
            {"name": "primaryPurpose (Task)", "value": task, "tier": "Critical", "category": "Metadata"},
            {"name": "suppliedBy (Supplier)", "value": supplier, "tier": "Critical", "category": "Metadata"},
            {"name": "name", "value": str(meta_comp.get("name", "N/A")), "tier": "Critical", "category": "Component Basic"},
            {"name": "type", "value": str(ml_model.get("type", "N/A")), "tier": "Critical", "category": "Component Basic"},
            {"name": "purl", "value": purl, "tier": "Important", "category": "Component Basic"},
            {"name": "description", "value": desc, "tier": "Important", "category": "Component Basic"},
            {"name": "licenses", "value": licenses, "tier": "Important", "category": "Component Basic"},
            {"name": "typeOfModel (Architecture)", "value": arch, "tier": "Important", "category": "Model Card"},
            {"name": "Approach", "value": approach, "tier": "Supplementary", "category": "Model Card"},
            {"name": "Downloads", "value": downloads, "tier": "Supplementary", "category": "Model Card"},
            {"name": "vocabSize", "value": vocab, "tier": "Supplementary", "category": "Model Card"},
            {"name": "tokenizerClass", "value": tok, "tier": "Supplementary", "category": "Model Card"},
            {"name": "safetyRiskAssessment", "value": safety, "tier": "Important", "category": "Model Card"},
            {"name": "datasets", "value": datasets, "tier": "Important", "category": "Model Card"},
            {"name": "ethicalConsiderations", "value": ethical, "tier": "Important", "category": "Model Card"},
            {"name": "energyConsumption", "value": energy, "tier": "Important", "category": "Model Card"},
            {"name": "hyperparameter", "value": hyper, "tier": "Important", "category": "Model Card"},
            {"name": "technicalLimitations", "value": tech_limit, "tier": "Important", "category": "Model Card"},
            {"name": "intendedUse", "value": intended, "tier": "Important", "category": "Model Card"},
            {"name": "downloadLocation", "value": download_loc, "tier": "Important", "category": "External References"}
        ]

        invalid_vals = ["N/A", "None", "Unknown", "0", "[]", "{}"]
        score_req = sum(1 for f in fields_to_check if f["category"] == "Required Fields" and f["value"] not in invalid_vals)
        score_meta = sum(1 for f in fields_to_check if f["category"] == "Metadata" and f["value"] not in invalid_vals)
        score_comp = sum(1 for f in fields_to_check if f["category"] == "Component Basic" and f["value"] not in invalid_vals)
        score_card = sum(1 for f in fields_to_check if f["category"] == "Model Card" and f["value"] not in invalid_vals)
        score_ext = sum(1 for f in fields_to_check if f["category"] == "External References" and f["value"] not in invalid_vals)

        max_req, max_meta, max_comp, max_card, max_ext = 4, 3, 5, 12, 1
        total_score = int(((score_req/max_req)*20) + ((score_meta/max_meta)*15) + ((score_comp/max_comp)*25) + ((score_card/max_card)*30) + ((score_ext/max_ext)*10))
        
        def get_color(pct):
            if pct >= 80: return "#22c55e"
            if pct >= 50: return "#f59e0b"
            return "#ef4444"
            
        def get_tier_badge(tier):
            if tier == "Critical": return "<span style='color: #ef4444; font-weight: bold;'>Critical</span>"
            if tier == "Important": return "<span style='color: #f59e0b; font-weight: bold;'>Important</span>"
            return "<span style='color: #3b82f6; font-weight: bold;'>Supplementary</span>"

        checklist_rows = ""
        for f in fields_to_check:
            is_present = f["value"] not in invalid_vals
            status_icon = "<span style='color:#22c55e; font-weight:bold;'>✔</span>" if is_present else "<span style='color:#ef4444; font-weight:bold;'>✘</span>"
            display_val = f["value"] if is_present else "Not found"
            checklist_rows += f"""<tr style="border-bottom:1px solid #e2e8f0;">
                <td style="padding:10px; text-align:center;">{status_icon}</td>
                <td style="padding:10px; font-family:monospace; font-weight:600; color:#334155;">{f['name']}</td>
                <td style="padding:10px; color:#475569; word-break: break-all;">{display_val}</td>
                <td style="padding:10px;">{get_tier_badge(f['tier'])}</td>
                <td style="padding:10px; color:#64748b; font-size: 13px;">{f['category']}</td>
            </tr>"""

        checklist_html = f"""
        <table>
            <thead>
                <tr style="background:#f8fafc; border-bottom:1px solid #e2e8f0;">
                    <th style="padding:12px; text-align:center; width:60px;">Status</th>
                    <th style="padding:12px; text-align:left; width:200px;">Field Name</th>
                    <th style="padding:12px; text-align:left;">Value / Status</th>
                    <th style="padding:12px; text-align:left; width:120px;">Tier</th>
                    <th style="padding:12px; text-align:left; width:150px;">Score Category</th>
                </tr>
            </thead>
            <tbody>
                {checklist_rows}
            </tbody>
        </table>
        """

        sbom_html = f"""
        <div style="background:#fff; border:1px solid #e2e8f0; border-radius:8px; padding:25px; margin-bottom:20px;">
            <div style="display:flex; align-items:center; margin-bottom:20px;">
                <h1 style="margin:0; font-size:36px; color:#1e293b; margin-right:20px;">{total_score}/100</h1>
                <div style="flex-grow:1; background:#f1f5f9; height:20px; border-radius:10px; overflow:hidden;">
                    <div style="width:{total_score}%; background:{get_color(total_score)}; height:100%;"></div>
                </div>
            </div>
            <table>
                <thead>
                    <tr style="background:#f8fafc; border-bottom:1px solid #e2e8f0;">
                        <th style="padding:12px; text-align:left;">Category</th>
                        <th style="padding:12px; text-align:left; width:80px;">Score</th>
                        <th style="padding:12px; text-align:left;">Progress</th>
                    </tr>
                </thead>
                <tbody>
                    <tr style="border-bottom:1px solid #e2e8f0;">
                        <td style="padding:12px; font-weight:600;">Required Fields</td><td style="padding:12px;">{score_req}/{max_req}</td>
                        <td style="padding:12px;"><div style="background:{get_color((score_req/max_req)*100)}; color:white; text-align:center; border-radius:4px; width:{(score_req/max_req)*100 if score_req > 0 else 5}%; font-size:12px;">{int((score_req/max_req)*100)}%</div></td>
                    </tr>
                    <tr style="border-bottom:1px solid #e2e8f0;">
                        <td style="padding:12px; font-weight:600;">Metadata</td><td style="padding:12px;">{score_meta}/{max_meta}</td>
                        <td style="padding:12px;"><div style="background:{get_color((score_meta/max_meta)*100)}; color:white; text-align:center; border-radius:4px; width:{(score_meta/max_meta)*100 if score_meta > 0 else 5}%; font-size:12px;">{int((score_meta/max_meta)*100)}%</div></td>
                    </tr>
                    <tr style="border-bottom:1px solid #e2e8f0;">
                        <td style="padding:12px; font-weight:600;">Component Basic</td><td style="padding:12px;">{score_comp}/{max_comp}</td>
                        <td style="padding:12px;"><div style="background:{get_color((score_comp/max_comp)*100)}; color:white; text-align:center; border-radius:4px; width:{(score_comp/max_comp)*100 if score_comp > 0 else 5}%; font-size:12px;">{int((score_comp/max_comp)*100)}%</div></td>
                    </tr>
                    <tr style="border-bottom:1px solid #e2e8f0;">
                        <td style="padding:12px; font-weight:600;">Model Card</td><td style="padding:12px;">{score_card}/{max_card}</td>
                        <td style="padding:12px;"><div style="background:{get_color((score_card/max_card)*100)}; color:white; text-align:center; border-radius:4px; width:{(score_card/max_card)*100 if score_card > 0 else 5}%; font-size:12px;">{int((score_card/max_card)*100)}%</div></td>
                    </tr>
                    <tr>
                        <td style="padding:12px; font-weight:600;">External References</td><td style="padding:12px;">{score_ext}/{max_ext}</td>
                        <td style="padding:12px;"><div style="background:{get_color((score_ext/max_ext)*100)}; color:white; text-align:center; border-radius:4px; width:{(score_ext/max_ext)*100 if score_ext > 0 else 5}%; font-size:12px;">{int((score_ext/max_ext)*100)}%</div></td>
                    </tr>
                </tbody>
            </table>
        </div>
        """

    # --- 4. CONDITIONAL AIBOM INCLUSION (ONLY FOR HUGGING_FACE) ---
    aibom_nav_html = ""
    aibom_section_html = ""
    
    if source_type_raw == "HUGGING_FACE":
        aibom_nav_html = """
        <div class="divider"></div>
        <a href="#aibom" class="aibom-link">AIBOM Transparency</a>
        <a href="#checklist" class="aibom-link">Field Checklist</a>
        """
        
        aibom_section_html = f"""
        <div class="plane plane-header-aibom">
            <h2 id="aibom" class="plane-title" style="color: var(--aibom-purple);">AIBOM Transparency Report</h2>
            <p style="color: var(--text-muted); margin-bottom: 25px;">Software Bill of Materials (SBOM) completeness evaluated against industry standards.</p>
            
            {sbom_html}
            
            <h3 id="checklist" class="section-title">Field Completeness Checklist</h3>
            <details open>
                <summary>View Granular Field Data</summary>
                {checklist_html}
            </details>
        </div>
        """

    # --- 5. HTML ASSEMBLY ---
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>AI Model Scan Report - {model_name}</title>
        <style>
            :root {{
                --prisma-teal: #025B6D;
                --prisma-light: #00829B;
                --aibom-purple: #6e41ab;
                --bg-light: #f8fafc;
                --text-main: #334155;
                --text-muted: #64748b;
            }}
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; color: var(--text-main); margin: 0; padding: 0 0 40px 0; background-color: #eef2f5; }}
            
            .page-container {{ max-width: 1400px; margin: auto; padding: 20px; }}
            .header {{ background: linear-gradient(90deg, var(--prisma-teal) 0%, var(--prisma-light) 100%); color: white; padding: 30px 40px; border-radius: 12px; margin-bottom: 30px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
            .header h1 {{ margin: 0; font-size: 28px; font-weight: 300; letter-spacing: 0.5px; }}
            .header h2 {{ margin: 5px 0 0 0; font-size: 16px; color: #e0f2f5; font-weight: normal; }}

            .content-layout {{ display: flex; gap: 40px; align-items: flex-start; }}
            
            .toc-sleek {{ position: sticky; top: 20px; width: 220px; flex-shrink: 0; padding-top: 10px; }}
            .toc-sleek .toc-header {{ font-size: 11px; font-weight: 700; text-transform: uppercase; color: var(--text-muted); letter-spacing: 1px; margin-bottom: 12px; padding-left: 12px; }}
            .toc-sleek a {{ display: block; text-decoration: none; color: var(--text-main); font-size: 14px; font-weight: 500; padding: 8px 12px; margin-bottom: 4px; border-radius: 6px; transition: all 0.2s ease; }}
            .toc-sleek a:hover {{ background: #e2e8f0; color: var(--prisma-teal); font-weight: 600; }}
            .toc-sleek .divider {{ height: 1px; background: #cbd5e1; margin: 15px 12px; }}
            .toc-sleek a.aibom-link:hover {{ color: var(--aibom-purple); }}

            .main-content {{ flex-grow: 1; min-width: 0; }}
            
            .plane {{ background: #fff; padding: 40px; box-shadow: 0 8px 16px rgba(0,0,0,0.06); border-radius: 12px; margin-bottom: 30px; }}
            .plane-header-security {{ border-top: 6px solid var(--prisma-light); }}
            .plane-header-aibom {{ border-top: 6px solid var(--aibom-purple); }}
            
            .plane-title {{ font-size: 24px; font-weight: bold; margin-top: 0; padding-bottom: 15px; border-bottom: 2px solid #e2e8f0; scroll-margin-top: 30px; }}
            .section-title {{ color: #1e293b; padding-bottom: 5px; margin-top: 35px; font-size: 18px; scroll-margin-top: 30px; }}
            
            details {{ background: var(--bg-light); border: 1px solid #e2e8f0; border-radius: 8px; padding: 5px 20px 20px 20px; margin-bottom: 20px; box-shadow: inset 0 2px 4px rgba(0,0,0,0.02); }}
            summary {{ font-weight: 600; font-size: 15px; color: #0f172a; cursor: pointer; padding: 15px 0 0 0; outline: none; list-style: none; }}
            summary::-webkit-details-marker {{ display: none; }}
            summary::before {{ content: '▶'; display: inline-block; width: 25px; transition: transform 0.2s; font-size: 12px; color: var(--prisma-light); }}
            details[open] summary::before {{ transform: rotate(90deg); }}
            details[open] summary {{ margin-bottom: 15px; border-bottom: 1px dashed #cbd5e1; padding-bottom: 10px; }}
            
            .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-top: 20px; }}
            .info-box {{ background: var(--bg-light); padding: 20px; border-radius: 8px; border-left: 4px solid var(--prisma-light); }}
            .badge {{ padding: 4px 10px; border-radius: 12px; font-size: 12px; font-weight: bold; color: white; }}
            .badge-passed {{ background-color: #22c55e; }}
            .badge-failed {{ background-color: #ef4444; }}
            .badge-state {{ background-color: #f59e0b; color: #fff; }}
            
            .remediation-card {{ border: 1px solid #e2e8f0; border-left: 4px solid var(--prisma-light); padding: 20px; margin-bottom: 15px; background: #fff; border-radius: 6px; }}
            .violation-card {{ border: 1px solid #fee2e2; border-left: 4px solid #ef4444; padding: 20px; margin-bottom: 10px; background: #fef2f2; border-radius: 6px; }}
            .violation-card h5 {{ margin: 0 0 8px 0; color: #b91c1c; font-size:16px; }}
            
            table {{ width: 100%; border-collapse: collapse; margin-top: 15px; border-radius: 8px; overflow: hidden; background: #fff; }}
            th, td {{ border: 1px solid #e2e8f0; padding: 12px 15px; text-align: left; font-size: 14px; }}
            th {{ background-color: #f1f5f9; color: var(--text-main); font-weight: 600; }}

            @media print {{
                body {{ background: #fff; padding: 0; }}
                .toc-sleek {{ display: none; }}
                .content-layout {{ display: block; }}
                .plane {{ box-shadow: none; border: 1px solid #e2e8f0; margin-bottom: 20px; page-break-inside: avoid; }}
                details {{ border: none; background: transparent; padding: 0; box-shadow: none; }}
                details[open] summary {{ border-bottom: none; }}
                summary::before {{ display: none; }}
                summary {{ pointer-events: none; padding-bottom: 10px; }}
                * {{ -webkit-print-color-adjust: exact !important; print-color-adjust: exact !important; }}
                .plane-header-aibom {{ page-break-before: always; }}
            }}
        </style>
    </head>
    <body>
        <div class="page-container">
            <div class="header">
                <h1>Palo Alto Networks | PRISMA AIRS™</h1>
                <h2>AI Model Security Scan Report - {scan_uuid}</h2>
            </div>

            <div class="content-layout">
                <nav class="toc-sleek">
                    <div class="toc-header">Report Navigation</div>
                    <a href="#overview">Scan Overview</a>
                    <a href="#evaluations">Evaluation Results</a>
                    <a href="#violations">Violation Details</a>
                    <a href="#remediations">Remediations</a>
                    {aibom_nav_html}
                </nav>

                <div class="main-content">
                    <div class="plane plane-header-security">
                        <h2 class="plane-title" style="color: var(--prisma-teal);">Security Scan Analysis</h2>
                        
                        <h3 id="overview" class="section-title" style="margin-top: 0;">Scan Overview</h3>
                        <div class="grid">
                            <div class="info-box">
                                <p><strong>Scan Type:</strong> {scan_type_display}</p>
                                <p><strong>Target Model:</strong> {model_name}</p>
                                <p><strong>Security Group:</strong> {sec_group}</p>
                                <p><strong>Scanner Version:</strong> {scanner_version}</p>
                            </div>
                            <div class="info-box">
                                <p><strong>Executed At:</strong> {executed_at}</p>
                                <p><strong>Scan Status:</strong> Completed</p>
                                <p><strong>Evaluation Outcome:</strong> <strong style="color: {outcome_color};">{eval_outcome}</strong></p>
                                <p><strong>Rules:</strong> {total_rules} Total | <span style="color: #22c55e;">{rules_passed} Passed</span> | <span style="color: #ef4444;">{rules_failed} Failed</span></p>
                            </div>
                        </div>

                        <h3 id="evaluations" class="section-title">Full Evaluation Results</h3>
                        <details open>
                            <summary>View All Evaluations ({len(e_list)})</summary>
                            <table>
                                <thead><tr><th>Rule Name</th><th>Description</th><th>Status</th></tr></thead>
                                <tbody>{eval_rows_html}</tbody>
                            </table>
                        </details>

                        <h3 id="violations" class="section-title">Violation Details ({len(v_list)} Found)</h3>
                        {f'<details open><summary>View Violations</summary>{violations_html}</details>' if violations_html else '<p style="color: var(--text-muted);">No file violations found.</p>'}

                        <h3 id="remediations" class="section-title">Recommendations & Remediation</h3>
                        {f'<details open><summary>View Remediation Steps</summary>{remediations_html}</details>' if remediations_html else '<p style="color: var(--text-muted);">No critical actions required.</p>'}
                    </div>

                    {aibom_section_html}
                    
                    <div style="text-align: center; color: #94a3b8; font-size: 12px; margin-top: 20px;">
                        Report generated via Prisma AIRS Model Scanning SDK
                    </div>
                </div>
            </div>
        </div>
    </body>
    </html>
    """
    with open(output_filename, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"\n✅ Report successfully generated: {output_filename}")