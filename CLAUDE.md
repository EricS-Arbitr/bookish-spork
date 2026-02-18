# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is an educational content repository for cybersecurity training materials (CDIH/CDISS course program). It contains structured lessons and labs for Cyber Defense Incident Handler / Cyber Defense Incident Service Specialist training. The content targets DoD/military cybersecurity operations.

There is no build system, test framework, CI/CD pipeline, or application code. All content is Markdown files with PNG screenshots, originally exported from Confluence (evidenced by UUID-based filenames).

## Repository Structure

All files live in the root directory (no subdirectories):

- **Course outline:** `CDIH CDISS Course Outlines *.md` — defines the overall course structure
- **Lessons (15 files):** `Lesson *.md` — instructional content covering cybersecurity topics (network infrastructure, defense tools, access control, cloud security, DoD frameworks, RMF, hardening, etc.)
- **Labs (18 files):** `LAB *.md` — hands-on exercises corresponding to lessons (Arkime, Zeek, Suricata, Sysmon, Wazuh, Windows Defender, VPN, backup/recovery, etc.)
- **Images (102 PNG files):** Screenshots and diagrams referenced by the Markdown files, mostly named with UUIDs

## Content Conventions

- Lessons and labs follow a consistent naming pattern: `Lesson <Topic> <uuid>.md` and `LAB <Topic> <uuid>.md`
- Images are referenced by their UUID-based filenames
- Content assumes prerequisite knowledge: Network+, Security+, Windows administration, Active Directory
- References DoD-specific frameworks and instructions (NCDOC, CJCSM, SECNAVINST, RMF)

## License

GPL-3.0
