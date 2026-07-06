import json
from typing import List, Optional
from loguru import logger
from openai import OpenAI

from src.sdk.key_manager import get_key_manager
from src.intelligence.engine import Finding, Severity, Confidence

class FindingExtractor:
    """
    Evaluates raw tool outputs using an LLM to extract structured Finding objects.
    """
    def __init__(self, client: Optional[OpenAI] = None, model: Optional[str] = None):
        km = get_key_manager()
        self._managed_client = client is None
        if client:
            self.client = client
            self.model = model or km.get_model()
        else:
            self.client = km.get_client()
            self.model = km.get_model()

    def _refresh_managed_client(self):
        """Keep secondary extraction calls aligned with the active provider."""
        if not self._managed_client:
            return get_key_manager()
        km = get_key_manager()
        self.client = km.get_client()
        self.model = km.get_model()
        return km

    def extract_findings(self, tool_name: str, tool_output: str, context: dict = None) -> List[Finding]:
        """
        Extract structured findings from a raw tool output using the LLM.
        """
        km = self._refresh_managed_client()
        try:
            remaining = km.current_rate_limit_remaining()
            if remaining > 0:
                logger.debug(
                    f"FindingExtractor skipped: current LLM key is rate-limited for {remaining:.0f}s"
                )
                return []
        except Exception:
            pass

        # Smart Token Management / Semantic Truncation
        if len(tool_output) > 20000:
            is_json = tool_output.strip().startswith("{") or tool_output.strip().startswith("[")
            is_html = "<html" in tool_output[:500].lower() or "<body" in tool_output[:500].lower()
            
            if is_html:
                import re
                tool_output = re.sub(r'<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>', '', tool_output, flags=re.IGNORECASE)
                tool_output = re.sub(r'<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>', '', tool_output, flags=re.IGNORECASE)
            
            if len(tool_output) > 20000:
                if is_json:
                    head = tool_output[:9500]
                    tail = tool_output[-9500:]
                    tool_output = head + "\n... [TRUNCATED JSON ARRAY/DICT ITEMS] ...\n" + tail
                else:
                    tool_output = tool_output[:10000] + "\n...[TRUNCATED]...\n" + tool_output[-10000:]
            
        prompt = f"""You are an Expert Security Intelligence Extractor. 
Analyze the output from '{tool_name}' for target context: {context if context else 'General web target'}.

### EXTRACTION OBJECTIVES:
1. **Identify Vulnerabilities**: Extract technical flaws with proof (SQLi, XSS, etc.).
2. **Context Clues (Logic Hunting)**: Extract "High-Value" keys/patterns (is_admin, balance, v1/internal, etc.) as MEDIUM severity FINDINGS.
3. **WAF/Blockers**: Identify if the output indicates a WAF block or IP ban.

### DISCARD CRITERIA (ANTI-FP):
- Discard generic 404/403 pages unless they contain sensitive tech signatures.
- Discard "0 results found" or empty directory listings.
- Discard theoretical "could be vulnerable" without a specific status code or response snippet.

### OUTPUT FORMAT:
Respond ONLY with a JSON object.
{{
  "findings": [
    {{
      "severity": "INFO|LOW|MEDIUM|HIGH|CRITICAL",
      "confidence": "TENTATIVE|FIRM|CERTAIN",
      "description": "Short, impact-focused title",
      "reasoning": "Explain WHY this is a finding (especially for logic clues)",
      "evidence": "Raw string/line from tool output",
      "remediation_hints": "Quick fix"
    }}
  ]
}}

=== TOOL OUTPUT ===
{tool_output}
"""
        findings_out = []
        import time
        max_retries = 3
        
        for attempt in range(max_retries):
            try:
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.0,
                    response_format={"type": "json_object"},
                    timeout=120.0
                )
                
                # ── Defensive null-checks ──────────────────────────────────────
                # Some providers return None/empty choices on content-filter
                # triggers, rate-limit soft-fails, or malformed responses.
                if response is None:
                    logger.warning("FindingExtractor: LLM returned None response")
                    break
                if not hasattr(response, 'choices') or not response.choices:
                    logger.warning("FindingExtractor: LLM response has no choices")
                    break
                
                message = response.choices[0].message if response.choices[0] else None
                if message is None:
                    logger.warning("FindingExtractor: LLM response choice has no message")
                    break
                    
                content = message.content
                if not content:
                    break
                
                # Robust JSON extraction to handle models that wrap output in markdown or conversational filler
                content = content.strip()
                if "```json" in content:
                    content = content.split("```json")[1].split("```")[0].strip()
                elif "```" in content:
                    content = content.split("```")[1].split("```")[0].strip()
                    
                start_idx = content.find('{')
                end_idx = content.rfind('}')
                if start_idx != -1 and end_idx != -1 and end_idx >= start_idx:
                    content = content[start_idx:end_idx+1]
                    
                data = json.loads(content)
                findings_data = data.get("findings", [])
                
                for item in findings_data:
                    if not isinstance(item, dict):
                        continue
                        
                    sev_str = item.get("severity", "INFO").upper()
                    conf_str = item.get("confidence", "TENTATIVE").upper()
                    
                    try:
                        sev = Severity[sev_str]
                    except KeyError:
                        sev = Severity.INFO
                        
                    try:
                        conf = Confidence[conf_str]
                    except KeyError:
                        conf = Confidence.TENTATIVE
                        
                    finding = Finding(
                        tool=tool_name,
                        description=item.get("description", "Unknown finding"),
                        severity=sev,
                        confidence=conf,
                        evidence=item.get("evidence", ""),
                        remediation_hints=item.get("remediation_hints")
                    )
                    findings_out.append(finding)
                
                break  # Success
                    
            except json.JSONDecodeError as e:
                logger.warning(f"FindingExtractor: malformed JSON from LLM: {e}")
                break
            except Exception as e:
                error_type = type(e).__name__
                is_rate_limit = "RateLimit" in error_type or "429" in str(e)
                provider_switched = False
                if self._managed_client:
                    try:
                        provider_switched = km.record_failure(str(e))
                        if provider_switched and attempt < max_retries - 1:
                            km = self._refresh_managed_client()
                            continue
                    except Exception as failure_record_err:
                        logger.debug(f"FindingExtractor failed to record provider failure: {failure_record_err}")
                
                if is_rate_limit and attempt < max_retries - 1:
                    sleep_time = 3 ** attempt
                    logger.debug(f"FindingExtractor rate limited. Retrying in {sleep_time}s...")
                    time.sleep(sleep_time)
                    continue
                    
                if "Timeout" in error_type or "Connection" in error_type or "APIError" in error_type or is_rate_limit:
                    logger.debug(f"FindingExtractor LLM API Request Failed ({error_type}): {e}")
                else:
                    logger.debug(f"FindingExtractor failed to parse LLM response: {error_type}: {e}")
                break
            
        return findings_out
