from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from enum import Enum
from datetime import datetime
import time
import logging
import uuid

logger = logging.getLogger("redteam.attacks")


class OWASPCategory(Enum):
    """OWASP Top 10 for LLM Applications 2025."""
    LLM01_PROMPT_INJECTION = "LLM01: Prompt Injection"
    LLM02_SENSITIVE_INFO = "LLM02: Sensitive Information Disclosure"
    LLM03_SUPPLY_CHAIN = "LLM03: Supply Chain Vulnerabilities"
    LLM04_DATA_POISONING = "LLM04: Data and Model Poisoning"
    LLM05_IMPROPER_OUTPUT = "LLM05: Improper Output Handling"
    LLM06_EXCESSIVE_AGENCY = "LLM06: Excessive Agency"
    LLM07_SYSTEM_PROMPT_LEAK = "LLM07: System Prompt Leakage"
    LLM08_VECTOR_EMBEDDING = "LLM08: Vector and Embedding Weaknesses"
    LLM09_MISINFORMATION = "LLM09: Misinformation"
    LLM10_UNBOUNDED_CONSUMPTION = "LLM10: Unbounded Consumption"
    JAILBREAK = "Jailbreak"
    BIAS = "Bias Detection"
    TOXICITY = "Toxicity"


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class AttackResult:
    """Represents the result of a single attack test."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    attack_name: str = ""
    attack_module: str = ""
    owasp_category: OWASPCategory = OWASPCategory.LLM01_PROMPT_INJECTION
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    # Test details
    prompt: str = ""
    system_prompt_used: str = ""
    response: str = ""
    
    # Evaluation
    success: bool = False
    severity: Severity = Severity.LOW
    confidence: float = 0.0
    
    # Descriptions
    description: str = ""
    remediation: str = ""
    cwe_id: str = ""
    
    # Judge evaluation
    judge_reasoning: str = ""
    judge_raw: Dict[str, Any] = field(default_factory=dict)
    
    # Metadata
    latency: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "attack_name": self.attack_name,
            "attack_module": self.attack_module,
            "owasp_category": self.owasp_category.value,
            "timestamp": self.timestamp,
            "prompt": self.prompt,
            "response": self.response[:1000],
            "success": self.success,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "description": self.description,
            "remediation": self.remediation,
            "cwe_id": self.cwe_id,
            "judge_reasoning": self.judge_reasoning,
            "latency": self.latency,
        }


class BaseAttack(ABC):
    """Abstract base class for all attack modules."""
    
    name: str = "base_attack"
    description: str = "Base attack module"
    owasp_category: OWASPCategory = OWASPCategory.LLM01_PROMPT_INJECTION
    cwe_id: str = ""
    remediation_advice: str = ""
    
    def __init__(self, target_adapter, judge=None, config: dict = None):
        self.target = target_adapter
        self.judge = judge
        self.config = config or {}
        self.results: List[AttackResult] = []
        self.system_prompt = self.config.get("system_prompt", "You are a helpful assistant.")
    
    @abstractmethod
    def generate_test_cases(self) -> List[Dict[str, Any]]:
        """Generate test cases. Each dict has at least 'prompt' and optionally 'system_prompt', 'metadata'."""
        pass
    
    def evaluate_response(self, test_case: dict, response: str) -> AttackResult:
        """
        Evaluate a response. Uses LLM judge if available, otherwise falls back to rules.
        """
        if self.judge:
            return self._judge_evaluate(test_case, response)
        return self._rule_evaluate(test_case, response)
    
    @abstractmethod
    def _rule_evaluate(self, test_case: dict, response: str) -> AttackResult:
        """Rule-based evaluation (fallback)."""
        pass
    
    def _judge_evaluate(self, test_case: dict, response: str) -> AttackResult:
        """LLM-as-judge evaluation."""
        judge_result = self.judge.evaluate(
            category=self.owasp_category,
            prompt=test_case["prompt"],
            response=response,
            system_prompt=test_case.get("system_prompt", self.system_prompt),
            metadata=test_case.get("metadata", {})
        )
        
        result = AttackResult(
            attack_name=self.name,
            attack_module=self.__class__.__name__,
            owasp_category=self.owasp_category,
            prompt=test_case["prompt"],
            system_prompt_used=test_case.get("system_prompt", self.system_prompt),
            response=response,
            success=judge_result.get("success", False),
            severity=Severity(judge_result.get("severity", "low")),
            confidence=judge_result.get("confidence", 0.0),
            description=judge_result.get("reasoning", ""),
            remediation=self.remediation_advice,
            cwe_id=self.cwe_id,
            judge_reasoning=judge_result.get("reasoning", ""),
            judge_raw=judge_result,
        )
        return result
    
    def run(self, max_tests: int = None) -> List[AttackResult]:
        """Execute all test cases for this attack module."""
        test_cases = self.generate_test_cases()
        
        if max_tests:
            test_cases = test_cases[:max_tests]
        
        logger.info(f"[{self.name}] Running {len(test_cases)} test cases...")
        
        results = []
        for i, test_case in enumerate(test_cases):
            try:
                sys_prompt = test_case.get("system_prompt", self.system_prompt)
                
                start = time.time()
                target_response = self.target.query_with_system(sys_prompt, test_case["prompt"])
                latency = time.time() - start
                
                result = self.evaluate_response(test_case, target_response.response)
                result.latency = latency
                result.metadata.update(test_case.get("metadata", {}))
                
                status = "⚠️  VULNERABLE" if result.success else "✅ PASSED"
                logger.info(f"  [{i+1}/{len(test_cases)}] {status} | "
                          f"Severity: {result.severity.value} | "
                          f"Confidence: {result.confidence:.0%}")
                
                results.append(result)
                
            except Exception as e:
                logger.error(f"  [{i+1}/{len(test_cases)}] ❌ ERROR: {e}")
                results.append(AttackResult(
                    attack_name=self.name,
                    attack_module=self.__class__.__name__,
                    owasp_category=self.owasp_category,
                    prompt=test_case["prompt"],
                    response=f"ERROR: {str(e)}",
                    success=False,
                    severity=Severity.INFO,
                    confidence=0.0,
                    description=f"Test failed with error: {e}",
                ))
            
            delay = self.config.get("delay_between_requests", 0.5)
            time.sleep(delay)
        
        self.results = results
        return results
