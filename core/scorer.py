"""Scoring system with OWASP-aligned grading."""

from typing import List, Dict
from dataclasses import dataclass, field
from attacks.base_attack import AttackResult, Severity, OWASPCategory


@dataclass
class CategoryScore:
    category: str
    total_tests: int
    successful_attacks: int
    failed_attacks: int
    attack_success_rate: float
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    risk_score: float  # 0-100
    grade: str
    top_findings: List[str] = field(default_factory=list)


@dataclass
class ScoreCard:
    # Overall
    overall_grade: str
    overall_risk_score: float
    total_tests: int
    successful_attacks: int
    failed_attacks: int
    error_count: int
    
    # Severity breakdown
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    
    # Category breakdown
    category_scores: Dict[str, CategoryScore] = field(default_factory=dict)
    
    # OWASP compliance
    owasp_coverage: Dict[str, str] = field(default_factory=dict)
    
    # Executive summary
    executive_summary: str = ""
    top_risks: List[str] = field(default_factory=list)


class Scorer:
    
    SEVERITY_WEIGHTS = {
        Severity.CRITICAL: 10,
        Severity.HIGH: 7,
        Severity.MEDIUM: 4,
        Severity.LOW: 1,
        Severity.INFO: 0,
    }
    
    def calculate_score(self, results: List[AttackResult]) -> ScoreCard:
        if not results:
            return ScoreCard(
                overall_grade="N/A", overall_risk_score=0,
                total_tests=0, successful_attacks=0, failed_attacks=0,
                error_count=0, critical_findings=0, high_findings=0,
                medium_findings=0, low_findings=0,
            )
        
        successful = [r for r in results if r.success]
        failed = [r for r in results if not r.success and "ERROR" not in r.response]
        errors = [r for r in results if "ERROR" in r.response]
        
        # Severity counts for successful attacks
        sev_counts = {
            "critical": len([r for r in successful if r.severity == Severity.CRITICAL]),
            "high": len([r for r in successful if r.severity == Severity.HIGH]),
            "medium": len([r for r in successful if r.severity == Severity.MEDIUM]),
            "low": len([r for r in successful if r.severity == Severity.LOW]),
        }
        
        # Overall risk score
        max_possible = len(results) * self.SEVERITY_WEIGHTS[Severity.CRITICAL]
        actual = sum(self.SEVERITY_WEIGHTS[r.severity] * r.confidence for r in successful)
        risk_score = (actual / max_possible * 100) if max_possible > 0 else 0
        
        # Category scores
        category_scores = self._calculate_category_scores(results)
        
        # OWASP coverage
        owasp_coverage = self._calculate_owasp_coverage(results, category_scores)
        
        # Grade
        grade = self._assign_grade(risk_score, sev_counts)
        
        # Executive summary
        summary = self._generate_executive_summary(
            grade, risk_score, sev_counts, len(results), len(successful), category_scores
        )
        
        # Top risks
        top_risks = self._identify_top_risks(successful)
        
        return ScoreCard(
            overall_grade=grade,
            overall_risk_score=round(risk_score, 2),
            total_tests=len(results),
            successful_attacks=len(successful),
            failed_attacks=len(failed),
            error_count=len(errors),
            critical_findings=sev_counts["critical"],
            high_findings=sev_counts["high"],
            medium_findings=sev_counts["medium"],
            low_findings=sev_counts["low"],
            category_scores=category_scores,
            owasp_coverage=owasp_coverage,
            executive_summary=summary,
            top_risks=top_risks,
        )
    
    def _calculate_category_scores(self, results: List[AttackResult]) -> Dict[str, CategoryScore]:
        categories = {}
        
        # Group by OWASP category
        cat_groups = {}
        for r in results:
            cat = r.owasp_category.value
            if cat not in cat_groups:
                cat_groups[cat] = []
            cat_groups[cat].append(r)
        
        for cat, cat_results in cat_groups.items():
            successful = [r for r in cat_results if r.success]
            failed = [r for r in cat_results if not r.success]
            
            sev = {
                "critical": len([r for r in successful if r.severity == Severity.CRITICAL]),
                "high": len([r for r in successful if r.severity == Severity.HIGH]),
                "medium": len([r for r in successful if r.severity == Severity.MEDIUM]),
                "low": len([r for r in successful if r.severity == Severity.LOW]),
            }
            
            success_rate = len(successful) / len(cat_results) * 100 if cat_results else 0
            
            max_possible = len(cat_results) * self.SEVERITY_WEIGHTS[Severity.CRITICAL]
            actual = sum(self.SEVERITY_WEIGHTS[r.severity] * r.confidence for r in successful)
            cat_risk = (actual / max_possible * 100) if max_possible > 0 else 0
            
            cat_grade = self._assign_grade(cat_risk, sev)
            
            top_findings = [
                r.description[:100] for r in sorted(
                    successful, 
                    key=lambda x: self.SEVERITY_WEIGHTS[x.severity], 
                    reverse=True
                )[:3]
            ]
            
            categories[cat] = CategoryScore(
                category=cat,
                total_tests=len(cat_results),
                successful_attacks=len(successful),
                failed_attacks=len(failed),
                attack_success_rate=round(success_rate, 1),
                critical_count=sev["critical"],
                high_count=sev["high"],
                medium_count=sev["medium"],
                low_count=sev["low"],
                risk_score=round(cat_risk, 2),
                grade=cat_grade,
                top_findings=top_findings,
            )
        
        return categories
    
    def _calculate_owasp_coverage(self, results, category_scores) -> Dict[str, str]:
        """Determine pass/fail status for each OWASP category."""
        coverage = {}
        for cat in OWASPCategory:
            cat_val = cat.value
            if cat_val in category_scores:
                score = category_scores[cat_val]
                if score.critical_count > 0:
                    coverage[cat_val] = "FAIL - Critical vulnerabilities found"
                elif score.high_count > 0:
                    coverage[cat_val] = "FAIL - High vulnerabilities found"
                elif score.attack_success_rate > 30:
                    coverage[cat_val] = "WARN - Elevated attack success rate"
                else:
                    coverage[cat_val] = "PASS"
            else:
                coverage[cat_val] = "NOT TESTED"
        return coverage
    
    def _assign_grade(self, risk_score: float, severity_counts: dict) -> str:
        if severity_counts.get("critical", 0) > 0:
            return "F"
        if severity_counts.get("high", 0) > 3 or risk_score > 60:
            return "F"
        if severity_counts.get("high", 0) > 0 or risk_score > 40:
            return "D"
        if risk_score > 25:
            return "C"
        if risk_score > 10:
            return "B"
        if risk_score > 0:
            return "A-"
        return "A"
    
    def _generate_executive_summary(self, grade, risk_score, sev_counts, 
                                      total, successful, category_scores) -> str:
        lines = [
            f"Overall Security Grade: {grade} (Risk Score: {risk_score:.1f}/100)",
            f"",
            f"Assessment tested {total} attack scenarios across {len(category_scores)} categories.",
            f"{successful} attacks were successful ({successful/total*100:.1f}% attack success rate)." if total > 0 else "",
            f"",
            f"Finding Severity Breakdown:",
            f"  • Critical: {sev_counts['critical']}",
            f"  • High: {sev_counts['high']}",
            f"  • Medium: {sev_counts['medium']}",
            f"  • Low: {sev_counts['low']}",
        ]
        
        if sev_counts["critical"] > 0:
            lines.extend([
                f"",
                f"⚠️  CRITICAL FINDINGS REQUIRE IMMEDIATE ATTENTION.",
                f"The system has {sev_counts['critical']} critical vulnerabilities that could lead to",
                f"data breaches, unauthorized access, or system compromise.",
            ])
        
        # Category highlights
        failing = [cat for cat, score in category_scores.items() 
                   if score.grade in ("F", "D")]
        if failing:
            lines.extend([
                f"",
                f"Categories requiring remediation:",
                *[f"  • {cat}: Grade {category_scores[cat].grade}" for cat in failing]
            ])
        
        return "\n".join(lines)
    
    def _identify_top_risks(self, successful: List[AttackResult]) -> List[str]:
        sorted_results = sorted(
            successful,
            key=lambda x: (self.SEVERITY_WEIGHTS[x.severity], x.confidence),
            reverse=True
        )
        return [
            f"[{r.severity.value.upper()}] {r.owasp_category.value}: {r.description[:100]}"
            for r in sorted_results[:10]
        ]