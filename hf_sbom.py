import datetime
import requests
import uuid

def fetch_hf_metadata(model_id):
    """Fetches high-level API metadata AND deep configuration files."""
    clean_id = str(model_id).replace("https://huggingface.co/", "")
    print(f"🌐 Fetching API and Config metadata for: {clean_id}...")
    
    combined_data = {
        "api": None,
        "config": {},
        "tokenizer": {}
    }
    
    # 1. Main API Data (Tags, Downloads, Datasets, Model Card)
    api_url = f"https://huggingface.co/api/models/{clean_id}"
    try:
        resp = requests.get(api_url, timeout=10)
        if resp.status_code == 200:
            combined_data["api"] = resp.json()
    except Exception as e:
        print(f"⚠️ HF API Error: {e}")

    # 2. Raw config.json (For Vocab Size & Architecture)
    config_url = f"https://huggingface.co/{clean_id}/raw/main/config.json"
    try:
        resp = requests.get(config_url, timeout=5)
        if resp.status_code == 200:
            combined_data["config"] = resp.json()
    except:
        pass

    # 3. Raw tokenizer_config.json (For Tokenizer Class)
    tok_url = f"https://huggingface.co/{clean_id}/raw/main/tokenizer_config.json"
    try:
        resp = requests.get(tok_url, timeout=5)
        if resp.status_code == 200:
            combined_data["tokenizer"] = resp.json()
    except:
        pass
        
    return combined_data if combined_data["api"] else None

def create_manual_sbom(scan_id, hf_combined_data):
    """Synthesizes a high-fidelity CycloneDX 1.7 M-SBOM including OWASP specific fields."""
    if not hf_combined_data: return None

    # Unpack our combined data
    hf_data = hf_combined_data.get("api", {})
    config_data = hf_combined_data.get("config", {})
    tok_data = hf_combined_data.get("tokenizer", {})

    model_id = str(hf_data.get("id", "N/A"))
    sha = str(hf_data.get("sha", "Unknown"))
    tags = hf_data.get("tags", [])
    card_data = hf_data.get("cardData") if isinstance(hf_data.get("cardData"), dict) else {}
    
    # --- 1. EXTRACT NEW OWASP FIELDS ---
    
    # Safely parse datasets (HF usually returns a list)
    datasets_raw = card_data.get("datasets", [])
    if isinstance(datasets_raw, list) and datasets_raw:
        datasets_str = ", ".join(str(d) for d in datasets_raw)
    elif isinstance(datasets_raw, str):
        datasets_str = datasets_raw
    else:
        datasets_str = "N/A"

    # Architecture & Tokenizer properties
    arch_list = config_data.get("architectures", [])
    arch = str(arch_list[0]) if arch_list else str(config_data.get("model_type", hf_data.get("config", {}).get("model_type", "N/A")))
    vocab = str(config_data.get("vocab_size", "N/A"))
    tok = str(tok_data.get("tokenizer_class", "N/A"))

    purl = f"pkg:huggingface/{model_id}@{sha}"
    
    # Generate a safe UUID for the CycloneDX Serial Number requirement
    serial_number = f"urn:uuid:{scan_id}" if scan_id else f"urn:uuid:{uuid.uuid4()}"
    
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "serialNumber": serial_number,  # Required by CycloneDX 1.7 standard
        "metadata": {
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "component": {
                "type": "machine-learning-model",
                "name": model_id.split('/')[-1] if '/' in model_id else model_id,
                "version": sha[:7],
                "description": "See Hugging Face repository for full model card details.",
                "purl": purl,
                "supplier": {"name": model_id.split('/')[0] if '/' in model_id else "Unknown"},
                "licenses": [{"license": {"id": str(card_data.get("license", "Unknown"))}}]
            }
        },
        "components": [
            {
                "type": "machine-learning-model",
                "bom-ref": purl,
                "name": model_id,
                "version": sha[:7],
                "modelCard": {
                    "modelParameters": {
                        "task": str(hf_data.get("pipeline_tag", "N/A")),
                        "approach": "Supervised" if "transformers" in tags else "N/A",
                        "datasets": datasets_str,
                        "hyperparameters": "N/A" # Usually requires parsing raw training args; defaults to N/A
                    },
                    "quantitativeAnalysis": {
                        "performanceMetrics": [{"type": "Total HF Downloads", "value": str(hf_data.get("downloads", 0))}]
                    },
                    "considerations": {
                        "users": [str(card_data.get("license", "Unknown"))],
                        "intendedUse": "N/A", 
                        "ethicalConsiderations": "N/A",
                        "technicalLimitations": "N/A",
                        "energyConsumption": "N/A",
                        "safetyRiskAssessment": "Please consult the original literature for potential biases."
                    }
                },
                "properties": [
                    {"name": "Architecture", "value": arch},
                    {"name": "vocabSize", "value": vocab},
                    {"name": "tokenizerClass", "value": tok}
                ]
            }
        ]
    }