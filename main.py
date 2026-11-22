import argparse
import sys
import os
from pathlib import Path


def main():
    # Windows consoles default to cp1252, which cannot print the banner/emoji.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(
        description="🔴 AI Red Team Assessment Tool - OWASP Top 10 for LLMs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full assessment with all categories
  python main.py --config config/config.yaml

  # Test specific OWASP categories
  python main.py --categories llm01_prompt_injection llm07_system_prompt_leakage

  # Quick scan (limited test cases per category)
  python main.py --quick

  # Run without LLM judge (rule-based only)  
  python main.py --no-judge

  # List available attack modules
  python main.py --list

  # Test one connection without running an assessment
  python main.py --provider ollama --model llama3.2 --check-target
        """
    )
    
    parser.add_argument("--config", default="config/config.yaml", 
                       help="Path to configuration file")
    parser.add_argument("--categories", nargs="+", default=None,
                       help="Attack categories to run")
    parser.add_argument("--list", action="store_true", 
                       help="List available attack modules")
    parser.add_argument("--quick", action="store_true",
                       help="Quick scan with reduced test cases")
    parser.add_argument("--no-judge", action="store_true",
                       help="Disable LLM-as-Judge (use rule-based evaluation)")
    parser.add_argument("--max-tests", type=int, default=None,
                       help="Maximum tests per category")
    parser.add_argument("--output-dir", default=None,
                       help="Override output directory")
    parser.add_argument("--provider", choices=("openai", "anthropic", "ollama"),
                       help="Override the target provider")
    parser.add_argument("--model", default=None,
                       help="Target model ID (required when changing providers)")
    parser.add_argument("--base-url", default=None,
                       help="OpenAI-compatible or Ollama endpoint URL")
    parser.add_argument("--api-key-env", default=None,
                       help="Name of the environment variable containing the API key")
    parser.add_argument("--check-target", action="store_true",
                       help="Send one health-check request without running an assessment")
    parser.add_argument("--provider-catalog", default="config/providers.yaml",
                       help="Path to OpenAI-compatible provider profiles")
    parser.add_argument("--list-providers", action="store_true",
                       help="List configured OpenAI-compatible provider profiles")
    parser.add_argument("--provider-profile",
                       help="Select an OpenAI-compatible provider profile")
    parser.add_argument("--cve", metavar="ID_OR_KEYWORD",
                       help="Look up an NVD CVE ID or recent keyword matches")
    parser.add_argument("--cve-days", type=int, default=30,
                       help="Keyword search publication window in days (1-120; default 30)")
    parser.add_argument("--cve-limit", type=int, default=10,
                       help="Maximum keyword results (1-100; default 10)")
    parser.add_argument("--interactive", action="store_true",
                       help="Choose a local Ollama model or hosted API interactively")
    parser.add_argument("--dashboard", action="store_true",
                       help="Open the read-only local report dashboard")
    parser.add_argument("--report-dir", default=None,
                       help="JSON report directory for the dashboard")
    parser.add_argument("--dashboard-port", type=int, default=8765,
                       help="Loopback port for the dashboard (default: 8765)")
    
    args = parser.parse_args()

    if args.dashboard:
        if (
            args.interactive or args.check_target or args.list or args.list_providers
            or args.cve is not None or args.provider or args.provider_profile
            or args.model or args.base_url or args.api_key_env or args.quick
            or args.categories or args.max_tests is not None or args.output_dir
            or args.no_judge
        ):
            parser.error("--dashboard cannot be combined with assessment or lookup options")
        if not 1 <= args.dashboard_port <= 65535:
            parser.error("--dashboard-port must be between 1 and 65535")
        from dashboard.app import DEFAULT_REPORT_DIR, serve_dashboard
        try:
            serve_dashboard(
                args.report_dir or DEFAULT_REPORT_DIR,
                args.dashboard_port,
                open_browser=True,
            )
        except OSError as exc:
            print(f"Dashboard failed to start: {exc}", file=sys.stderr)
            return 1
        return 0

    if args.interactive and (
        args.provider or args.model or args.base_url or args.api_key_env
        or args.provider_profile or args.list or args.list_providers
        or args.cve is not None
    ):
        parser.error("--interactive cannot be combined with target selection or listing options")

    if args.cve is not None:
        from core.cve_lookup import CveLookupError, format_cve, lookup_cves
        try:
            records, total = lookup_cves(args.cve, days=args.cve_days, limit=args.cve_limit)
        except ValueError as exc:
            parser.error(str(exc))
        except CveLookupError as exc:
            print(f"CVE lookup failed: {exc}", file=sys.stderr)
            return 1
        print(f"NVD: {total} matching CVEs; displaying {len(records)}.")
        if not records:
            print("No matching CVEs found.")
        for record in records:
            print(f"\n{format_cve(record)}")
        print("\nCVE matches do not establish that a specific deployment is affected.")
        return 0

    if args.list_providers or args.provider_profile:
        from core.provider_catalog import load_provider_catalog
        try:
            profiles = load_provider_catalog(args.provider_catalog)
        except ValueError as exc:
            parser.error(str(exc))
        if args.list_providers:
            for name, profile in sorted(profiles.items()):
                print(f"{name}: {profile.base_url} (key environment variable: {profile.api_key_env})")
            return 0
        if args.provider_profile not in profiles:
            parser.error(f"Unknown provider profile: {args.provider_profile}")
        if args.provider or args.base_url or args.api_key_env:
            parser.error("--provider-profile cannot be combined with --provider, --base-url, or --api-key-env")
        if not args.model or not args.model.strip():
            parser.error("--model is required with --provider-profile")
    
    # List attack modules
    if args.list:
        from core.engine import ATTACK_REGISTRY
        print("\n📋 Available Attack Modules:")
        print("─" * 60)
        for name, cls in ATTACK_REGISTRY.items():
            print(f"  🔹 {name}")
            print(f"     {cls.description}")
            print(f"     OWASP: {cls.owasp_category.value}")
            print(f"     CWE: {cls.cwe_id}")
            print()
        sys.exit(0)
    
    # Load config and apply overrides
    import yaml
    if not Path(args.config).exists():
        print(f"❌ Config file not found: {args.config}")
        print("   Run with --list to see available modules")
        sys.exit(1)
    
    with open(args.config) as f:
        config = yaml.safe_load(f)

    if not isinstance(config, dict) or not isinstance(config.get("target"), dict):
        parser.error("Configuration must contain a target mapping")

    target_config = config["target"]
    if args.interactive:
        from core.interactive_setup import configure_interactively
        try:
            configure_interactively(
                config, args.provider_catalog, no_judge=args.no_judge,
                check_target=args.check_target,
            )
        except ValueError as exc:
            print(f"Interactive setup failed: {exc}", file=sys.stderr)
            return 1
        except (EOFError, KeyboardInterrupt):
            print("\nInteractive setup cancelled.", file=sys.stderr)
            return 1
    if args.provider_profile:
        profile = profiles[args.provider_profile]
        target_config.update({
            "provider": "openai",
            "base_url": profile.base_url,
            "api_key_env": profile.api_key_env,
        })
    if args.provider and args.provider != target_config.get("provider"):
        if not args.model:
            parser.error("--model is required when changing providers")
        target_config["provider"] = args.provider
        target_config["base_url"] = None
        target_config["api_key_env"] = {
            "openai": "OPENAI_API_KEY",
            "anthropic": "ANTHROPIC_API_KEY",
            "ollama": None,
        }[args.provider]
    if args.model is not None:
        target_config["model"] = args.model
    if args.base_url is not None:
        target_config["base_url"] = args.base_url
    if args.api_key_env is not None:
        target_config["api_key_env"] = args.api_key_env
    if target_config.get("provider") == "anthropic" and args.base_url:
        parser.error("--base-url is supported for OpenAI-compatible and Ollama targets only")

    if args.check_target:
        from core.engine import ADAPTER_REGISTRY
        from requests.exceptions import RequestException
        provider = target_config.get("provider")
        adapter_class = ADAPTER_REGISTRY.get(provider)
        if adapter_class is None:
            parser.error(f"Unknown target provider: {provider}")
        try:
            target = adapter_class(target_config)
            if not target.health_check():
                print("Target returned an empty health-check response.", file=sys.stderr)
                return 1
        except (ValueError, ImportError, OSError, RequestException) as exc:
            print(f"Target health check failed: {exc}", file=sys.stderr)
            return 1
        print(f"Target health check passed: {provider} / {target_config.get('model')}")
        return 0
    
    # Apply CLI overrides
    if args.no_judge:
        config.setdefault("judge", {})["enabled"] = False
    
    if args.quick:
        config.setdefault("attacks", {})["max_tests_per_category"] = 5
    
    if args.max_tests:
        config.setdefault("attacks", {})["max_tests_per_category"] = args.max_tests
    
    if args.output_dir:
        config.setdefault("reporting", {})["output_dir"] = args.output_dir
    
    # Write modified config to temp file
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as tmp:
        yaml.dump(config, tmp)
        tmp_config = tmp.name
    
    try:
        from core.engine import RedTeamEngine
        
        engine = RedTeamEngine(tmp_config)
        result = engine.run_assessment(categories=args.categories)
        
        scorecard = result["scorecard"]
        
        # Exit code based on findings
        if scorecard.critical_findings > 0:
            sys.exit(2)
        elif scorecard.high_findings > 0:
            sys.exit(1)
        else:
            sys.exit(0)
            
    except KeyboardInterrupt:
        print("\n\n⚠️  Assessment interrupted by user.")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        os.unlink(tmp_config)


if __name__ == "__main__":
    sys.exit(main())
