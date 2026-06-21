"""Platform registry — defines file patterns for each agentic platform."""

from __future__ import annotations

from .models import Platform, PlatformSpec

PLATFORMS: dict[Platform, PlatformSpec] = {
    Platform.CURSOR: PlatformSpec(
        name=Platform.CURSOR,
        description="Cursor IDE agent configs (rules, skills, hooks, MCP, automations)",
        file_patterns=[
            ".cursor/rules/**/*.md",
            ".cursor/rules/**/*.mdc",
            ".cursor/skills/**/*.md",
            ".cursor/hooks.json",
            ".cursor/mcp.json",
            ".cursor/automations/**",
            "**/SKILL.md",
            "AGENTS.md",
            "AGENTS.override.md",
        ],
        dep_plant_paths=[
            "node_modules/**/AGENTS.md",
            "node_modules/**/.cursor/",
            "vendor/**/AGENTS.md",
            ".venv/**/AGENTS.md",
        ],
    ),
    Platform.CODEX: PlatformSpec(
        name=Platform.CODEX,
        description="OpenAI Codex / ChatGPT agent configs",
        file_patterns=[
            "AGENTS.md",
            ".codex/**",
            "codex.json",
            "codex.yaml",
        ],
        dep_plant_paths=[
            "node_modules/**/AGENTS.md",
        ],
    ),
    Platform.COPILOT: PlatformSpec(
        name=Platform.COPILOT,
        description="GitHub Copilot custom instructions",
        file_patterns=[
            ".github/copilot-instructions.md",
            ".github/copilot/**",
        ],
        dep_plant_paths=[],
    ),
    Platform.CLAUDE: PlatformSpec(
        name=Platform.CLAUDE,
        description="Anthropic Claude Code / Desktop configs",
        file_patterns=[
            "CLAUDE.md",
            ".claude/**",
            "claude_desktop_config.json",
            ".mcp.json",
        ],
        dep_plant_paths=[
            "node_modules/**/CLAUDE.md",
        ],
    ),
    Platform.WINDSURF: PlatformSpec(
        name=Platform.WINDSURF,
        description="Windsurf IDE rules and MCP configs",
        file_patterns=[
            ".windsurfrules",
            ".windsurf/rules/**",
            ".windsurf/mcp.json",
        ],
        dep_plant_paths=[],
    ),
    Platform.CLINE: PlatformSpec(
        name=Platform.CLINE,
        description="Cline / Continue extension configs",
        file_patterns=[
            ".clinerules",
            ".cline/**",
            ".continue/**",
            ".continue/config.json",
        ],
        dep_plant_paths=[],
    ),
    Platform.DEVIN: PlatformSpec(
        name=Platform.DEVIN,
        description="Devin / Cognition agent configs",
        file_patterns=[
            "devin.md",
            ".devin/**",
        ],
        dep_plant_paths=[],
    ),
    Platform.BEDROCK: PlatformSpec(
        name=Platform.BEDROCK,
        description="AWS Bedrock agent definitions",
        file_patterns=[
            "**/bedrock-agent*.json",
            "**/bedrock-agent*.yaml",
            "**/knowledge-base*.json",
        ],
        dep_plant_paths=[],
    ),
    Platform.LANGCHAIN: PlatformSpec(
        name=Platform.LANGCHAIN,
        description="LangChain / LangGraph agent YAML configs",
        file_patterns=[
            "**/agents.yaml",
            "**/agents.yml",
            "**/tools.yaml",
            "**/prompts/**/*.yaml",
            "**/langgraph.json",
        ],
        dep_plant_paths=[],
    ),
    Platform.CREWAI: PlatformSpec(
        name=Platform.CREWAI,
        description="CrewAI / AutoGPT crew and task configs",
        file_patterns=[
            "**/agents.yaml",
            "**/tasks.yaml",
            "**/crew.yaml",
            "autogpt/**/*.yaml",
        ],
        dep_plant_paths=[],
    ),
    Platform.GENERIC: PlatformSpec(
        name=Platform.GENERIC,
        description="Generic agent instruction files",
        file_patterns=[
            "**/AGENTS.md",
            "**/SYSTEM_PROMPT*.md",
            "**/system-prompt*.md",
            "**/.agent*",
        ],
        dep_plant_paths=[
            "node_modules/**/AGENTS.md",
            "vendor/**/AGENTS.md",
            ".venv/**/AGENTS.md",
            "packages/**/AGENTS.md",
        ],
    ),
}


def detect_platforms(target_path: str) -> list[Platform]:
    """Auto-detect which platforms have configs in the target path."""
    from pathlib import Path

    root = Path(target_path)
    detected: list[Platform] = []

    for platform, spec in PLATFORMS.items():
        if platform == Platform.GENERIC:
            continue
        for pattern in spec.file_patterns:
            if list(root.glob(pattern)):
                detected.append(platform)
                break

    if not detected:
        detected.append(Platform.GENERIC)

    return detected


def get_all_patterns(platforms: list[Platform]) -> list[str]:
    """Get combined file patterns for a set of platforms."""
    patterns: list[str] = []
    for p in platforms:
        spec = PLATFORMS[p]
        patterns.extend(spec.file_patterns)
        patterns.extend(spec.dep_plant_paths)
    return list(set(patterns))
