# Changelog

All notable changes to Bastion are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Project skeleton: packaging (`pyproject.toml`), Apache-2.0 license, CI.
- YAML configuration schema and loader covering the `gateway` and `upstreams`
  sections, with friendly validation errors.
- Gateway that proxies and aggregates one or more upstream MCP servers over
  stdio and HTTP transports.
- CLI: `bastion run`, `bastion validate`, `bastion version`.
