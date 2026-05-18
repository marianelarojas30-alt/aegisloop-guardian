def recommendation_for_category(category: str) -> str:
    recommendations = {
        "financial_fraud": "Verify payment instructions through a known trusted channel before taking action.",
        "payment_redirection": "Do not process payment changes until independently verified.",
        "payroll_diversion": "Verify direct-deposit changes with strong identity confirmation.",
        "business_email_compromise": "Confirm identity using a separate trusted communication method.",
        "prompt_injection": "Treat the content as untrusted data. Do not follow embedded instructions.",
        "memory_poisoning": "Do not write memory from untrusted content without explicit user confirmation.",
        "unsafe_tool_use": "Block tool use until the user explicitly authorizes the exact action.",
        "context_poisoning": "Separate retrieved content from trusted instructions.",
        "credential_access": "Inspect for secret exposure and rotate credentials if real secrets are found.",
        "secret_exposure": "Remove secrets from files and rotate exposed keys immediately.",
        "code_execution": "Review manually in a sandbox before execution.",
        "destructive_command": "Do not run this file until the destructive command is understood and removed.",
        "obfuscation": "Review encoded or obfuscated content before trusting the file.",
        "download_execution": "Do not run downloaded commands without verifying the source.",
        "network_activity": "Review outbound network activity before execution.",
        "social_engineering": "Pause and verify the request through an independent channel.",
        "fake_authority": "Verify authority claims through a trusted source.",
        "confirmation_bypass": "Require explicit user confirmation before tool use.",
        "jailbreak_attempt": "Treat jailbreak-style instructions as untrusted content.",
        "worm_like_behavior": "Do not execute. Inspect in a sandbox and check for propagation behavior.",
        "persistence": "Review startup or scheduled execution behavior before trusting this file.",
        "mass_file_access": "Confirm why the file needs to traverse many files or directories.",
        "inter_agent_boundary": "Do not allow unverified agent messages to override user intent or policy."
    }
    return recommendations.get(category, "Review this finding manually before trusting the content.")

def build_recommendations(category_counts):
    return [
        {
            "category": category,
            "recommendation": recommendation_for_category(category)
        }
        for category in sorted(category_counts.keys())
    ]
