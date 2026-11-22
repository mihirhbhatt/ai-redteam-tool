"""Main orchestration engine for the AI Red Team framework."""

import yaml
import time
import logging
from typing import List, Dict, Type, Optional
from datetime import datetime

from core.logger import configure_logging
from core.target import BaseTargetAdapter
from core.scorer import Scorer, ScoreCard
from core.judge import LLMJudge
from attacks.base_attack import BaseAttack, AttackResult

# Import all attack modules
from attacks.owasp.llm01_prompt_injection import LLM01PromptInjection
from attacks.owasp.llm02_sensitive_info_disclosure import LLM02SensitiveInfoDisclosure
from attacks.owasp.llm03_supply_chain import LLM03SupplyChain
from attacks.owasp.llm04_data_poisoning import LLM04DataPoisoning
from attacks.owasp.llm05_improper_output_handling import LLM05ImproperOutputHandling
from attacks.owasp.llm06_excessive_agency import LLM06ExcessiveAgency
from attacks.owasp.llm07_system_prompt_leakage import LLM07SystemPromptLeakage
from attacks.owasp.llm08_vector_embedding import LLM08VectorEmbedding
from attacks.owasp.llm09_misinformation import LLM09Misinformation
from attacks.owasp.llm10_unbounded_consumption import LLM10UnboundedConsumption
from attacks.jailbreak.crescendo import CrescendoAttack
from attacks.bias.bias_attack import BiasDetection
from attacks.toxicity.toxicity_attack import ToxicityAttack

# Import adapters
from adapters.openai_adapter import OpenAIAdapter, AnthropicAdapter, OllamaAdapter

from reports.report_generator import ReportGenerator

logger = logging.getLogger("redteam")


# ===== REGISTRIES =====
ATTACK_REGISTRY: Dict[str, Type[BaseAttack]] = {
    "llm01_prompt_injection": LLM01PromptInjection,
    "llm02_sensitive_info_disclosure": LLM02SensitiveInfoDisclosure,
    "llm03_supply_chain": LLM03SupplyChain,
    "llm04_data_poisoning": LLM04DataPoisoning,
    "llm05_improper_output_handling": LLM05ImproperOutputHandling,
    "llm06_excessive_agency": LLM06ExcessiveAgency,
    "llm07_system_prompt_leakage": LLM07SystemPromptLeakage,
    "llm08_vector_embedding": LLM08VectorEmbedding,
    "llm09_misinformation": LLM09Misinformation,
    "llm10_unbounded_consumption": LLM10UnboundedConsumption,
    "jailbreak_crescendo": CrescendoAttack,
    "bias_detection": BiasDetection,
    "toxicity": ToxicityAttack,
}

ADAPTER_REGISTRY: Dict[str, Type[BaseTargetAdapter]] = {
    "openai": OpenAIAdapter,
    "anthropic": AnthropicAdapter,
    "ollama": OllamaAdapter,
}


class RedTeamEngine:
    """Main engine that orchestrates the complete red team assessment."""
    
    def __init__(self, config_path: str = "config/config.yaml"):
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        self._setup_logging()
        
        # Initialize components
        self.target_adapter = self._create_adapter(self.config["target"])
        self.judge = self._create_judge()
        self.scorer = Scorer()
        self.report_generator = ReportGenerator(self.config)
        
        self.all_results: List[AttackResult] = []
        self.start_time = None
    
    def _setup_logging(self):
        log_config = self.config.get("logging", {})
        configure_logging(
            level=log_config.get("level", "INFO"),
            log_file=log_config.get("file", "./logs/redteam.log"),
            console=log_config.get("console", True),
        )
    
    def _create_adapter(self, config: dict) -> BaseTargetAdapter:
        provider = config.get("provider", "openai")
        adapter_cls = ADAPTER_REGISTRY.get(provider)
        if not adapter_cls:
            raise ValueError(f"Unknown provider: {provider}")
        return adapter_cls(config)
    
    def _create_judge(self) -> Optional[LLMJudge]:
        judge_config = self.config.get("judge", {})
        if not judge_config.get("enabled", False):
            logger.info("LLM Judge: DISABLED (using rule-based evaluation)")
            return None
        
        logger.info(f"LLM Judge: ENABLED (model: {judge_config.get('model', 'unknown')})")
        judge_adapter = self._create_adapter(judge_config)
        return LLMJudge(
            adapter=judge_adapter,
            templates_path=judge_config.get(
                "templates_path", 
                "config/judge_prompts/judge_templates.yaml"
            )
        )
    
    def run_assessment(self, categories: List[str] = None) -> Dict:
        """Run a complete red team assessment."""
        self.start_time = datetime.now()
        
        if categories is None:
            categories = self.config.get("attacks", {}).get(
                "enabled_categories", list(ATTACK_REGISTRY.keys())
            )
        
        system_prompt = self.config.get("target", {}).get("system_prompt", "")
        model_name = self.config.get("target", {}).get("model", "unknown")
        max_per_category = self.config.get("attacks", {}).get("max_tests_per_category", 50)
        
        self._print_banner()
        logger.info(f"Target Model: {model_name}")
        logger.info(f"Categories: {categories}")
        logger.info(f"Judge: {'Enabled' if self.judge else 'Disabled (rule-based)'}")
        
        # Health check
        if not self._health_check():
            raise ConnectionError("Target system health check failed")
        
        # Run each attack category
        self.all_results = []
        
        for cat_name in categories:
            if cat_name not in ATTACK_REGISTRY:
                logger.warning(f"Unknown category: {cat_name}, skipping...")
                continue
            
            attack_cls = ATTACK_REGISTRY[cat_name]
            attack = attack_cls(
                target_adapter=self.target_adapter,
                judge=self.judge,
                config={
                    **self.config.get("attacks", {}),
                    "system_prompt": system_prompt,
                }
            )
            
            logger.info(f"\n{'='*70}")
            logger.info(f"🔴 RUNNING: {attack.name}")
            logger.info(f"   {attack.description}")
            logger.info(f"   OWASP: {attack.owasp_category.value}")
            logger.info(f"   CWE: {attack.cwe_id}")
            logger.info(f"{'='*70}")
            
            start = time.time()
            results = attack.run(max_tests=max_per_category)
            elapsed = time.time() - start
            
            success_count = sum(1 for r in results if r.success)
            logger.info(f"\n   Completed: {len(results)} tests | "
                       f"{success_count} vulnerabilities found | "
                       f"{elapsed:.1f}s elapsed")
            
            self.all_results.extend(results)
        
        # Calculate final scores
        scorecard = self.scorer.calculate_score(self.all_results)
        
        # Generate reports
        target_info = {
            "provider": self.config["target"]["provider"],
            "model": model_name,
            "system_prompt_hash": hash(system_prompt),
            "assessment_date": self.start_time.isoformat(),
            "duration_seconds": (datetime.now() - self.start_time).total_seconds(),
        }
        
        report_paths = self.report_generator.generate_all_reports(
            self.all_results, scorecard, target_info
        )
        
        # Print final summary
        self._print_final_summary(scorecard, report_paths)
        
        return {
            "scorecard": scorecard,
            "results": self.all_results,
            "reports": report_paths,
        }
    
    def _health_check(self) -> bool:
        logger.info("Running health check...")
        try:
            response = self.target_adapter.query("Hello, this is a health check. Respond with 'OK'.")
            if response and response.response.strip():
                logger.info("✅ Health check passed")
                return True
        except Exception as e:
            logger.error(f"❌ Health check failed: {e}")
        return False
    
    def _print_banner(self):
        banner = """
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║   🔴  AI RED TEAM ASSESSMENT TOOL                                    ║
║                                                                      ║
║   OWASP Top 10 for LLM Applications                                 ║
║   With LLM-as-Judge Evaluation                                       ║
║                                                                      ║
║   ⚠️  FOR AUTHORIZED TESTING ONLY                                    ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
        """
        print(banner)
    
    def _print_final_summary(self, scorecard: ScoreCard, report_paths: dict):
        grade_emoji = {
            "A": "🟢", "A-": "🟢", "B": "🟡", 
            "C": "🟠", "D": "🔴", "F": "🔴"
        }
        
        emoji = grade_emoji.get(scorecard.overall_grade, "⚪")
        
        print(f"\n{'═'*70}")
        print(f"  ASSESSMENT COMPLETE")
        print(f"{'═'*70}")
        print(f"  {emoji} Overall Grade: {scorecard.overall_grade}")
        print(f"  📊 Risk Score: {scorecard.overall_risk_score}/100")
        print(f"  🧪 Total Tests: {scorecard.total_tests}")
        print(f"  ⚠️  Successful Attacks: {scorecard.successful_attacks}")
        print(f"  ✅ Blocked Attacks: {scorecard.failed_attacks}")
        print(f"  ❌ Errors: {scorecard.error_count}")
        print(f"{'─'*70}")
        print(f"  SEVERITY BREAKDOWN:")
        print(f"  🔴 Critical: {scorecard.critical_findings}")
        print(f"  🟠 High: {scorecard.high_findings}")
        print(f"  🟡 Medium: {scorecard.medium_findings}")
        print(f"  🟢 Low: {scorecard.low_findings}")
        print(f"{'─'*70}")
        print(f"  OWASP CATEGORY RESULTS:")
        for cat, score in scorecard.category_scores.items():
            status = "❌ FAIL" if score.grade in ("F", "D") else "⚠️  WARN" if score.grade == "C" else "✅ PASS"
            print(f"  {status} {cat}: {score.successful_attacks}/{score.total_tests} "
                  f"({score.attack_success_rate}%) | Grade: {score.grade}")
        print(f"{'─'*70}")
        
        if scorecard.top_risks:
            print(f"  TOP RISKS:")
            for i, risk in enumerate(scorecard.top_risks[:5], 1):
                print(f"  {i}. {risk}")
        
        print(f"{'─'*70}")
        print(f"  REPORTS:")
        for fmt, path in report_paths.items():
            print(f"  📄 {fmt.upper()}: {path}")
        print(f"{'═'*70}\n")
        
        # Executive summary
        if scorecard.executive_summary:
            print(f"\n📋 EXECUTIVE SUMMARY:")
            print(f"{'─'*70}")
            print(scorecard.executive_summary)
            print(f"{'─'*70}\n")
