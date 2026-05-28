# Prisma AIRS™ AI Model Scan Reporting Tool

An enterprise scanning reporting tool built for the **Palo Alto Networks Prisma AI Runtime Security (AIMS)** ecosystem. This utility orchestrates the ingestion of scan metadata, compliance rule evaluations, and threat violations to compile an offline-viewable, high-impact HTML security summary. For Hugging Face models, it automatically builds and evaluates an accompanying AI Software Bill of Materials (AIBOM) completeness checklist.

## Features

- 🛡️ **Comprehensive Security Aggregation:** Blends raw scan logs, compliance rule evaluations, and actionable file violations into one view.
- 🔍 **Deep Threat Intel Embedding:** Dynamically parses threat indices to yield embedded context markers (`insights_url` and `threat_kb_url`) when telemetry links are served by the API.
- 🎛️ **Native API Footprints:** Respects your API configuration directly by explicitly showing raw `source_type` mappings (`LOCAL`, `HUGGING_FACE`, etc.).
- 📦 **Conditional AIBOM Auditing:** Isolates and creates software transparency trackers natively when evaluated target types match `HUGGING_FACE`.
- 🖨️ **Print-Ready Stylesheets:** Preserves dedicated layouts for physical printing or system save-to-PDF pipeline runs.

## Project Structure

```text
├── view-full-report.py   # Orchestrator and application core runner
├── get_html.py           # Presentation layer (HTML & inline CSS engine)
├── violations.py         # Prisma SASE Client Credentials Auth & Violations ingestion
├── evaluations.py        # Prisma SASE Evaluations log fetching module
├── hf_sbom.py            # Hugging Face config extraction & CycloneDX generator
├── .env.example          # Sample environment credentials blueprint
└── .gitignore            # Keeps environment profiles out of public version control
```

## Prerequisites

- **Python:** `3.11` or `3.12`
- **Credentials:** Valid client credentials generated through the Palo Alto Networks SCM Portal.

## Package Dependencies

Install the required packages using pip:

```bash
pip install requests python-dotenv
```

## Configuration

1. Create a `.env` file in the root directory of this repository:
   ```bash
   touch .env
   ```

2. Populate the `.env` file with your verified Prisma instance secrets:
   ```env
   MODEL_SECURITY_CLIENT_ID="your_client_id_here"
   MODEL_SECURITY_CLIENT_SECRET="your_client_secret_here"
   TSG_ID="your_tenant_service_group_id_here"
   ```

## Usage

Execute the report orchestration manager by passing a valid Prisma Scan UUID string sequence as a CLI system argument:

```bash
python3 view-full-report.py <scan_id_uuid>
```

### Example Execution

```bash
python3 view-full-report.py d6d19abb-9640-4aff-bc59-602aa1cd9de2
```

Upon a successful API handshake sequence, an asset file named `<scan_id>_report.html` will be populated into your root project path.

---
*Built with the assistance of Gemini 3.5*