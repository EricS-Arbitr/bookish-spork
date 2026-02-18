# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is an educational content repository for cybersecurity training materials (CDIH/CDISS course program). It contains structured lessons and labs for Cyber Defense Incident Handler / Cyber Defense Incident Service Specialist training. The content targets DoD/military cybersecurity operations.

There is no build system, test framework, CI/CD pipeline, or application code. All content is Markdown files with PNG screenshots, originally exported from Confluence (evidenced by UUID-based filenames).

## Repository Structure

- **KSATs:** `Cyber Defense Infra Supp Spec-KSATs.xlsx` — the authoritative KSAT requirements that all training content must satisfy
- **Course outline:** `CDIH CDISS Course Outlines *.md` — defines the overall course structure
- **Lessons (15 files):** `Lesson *.md` — instructional content covering cybersecurity topics (network infrastructure, defense tools, access control, cloud security, DoD frameworks, RMF, hardening, etc.)
- **Labs (18 files):** `LAB *.md` — hands-on exercises corresponding to lessons (Arkime, Zeek, Suricata, Sysmon, Wazuh, Windows Defender, VPN, backup/recovery, etc.)
- **Images (102 PNG files):** Screenshots and diagrams referenced by the Markdown files, mostly named with UUIDs
- **References:** `references/` — doctrinal reference PDFs (CWPs, JP 3-12, etc.); git-ignored, available locally only

## Target Audience

The learners are fairly new to IT and cybersecurity. They:
- Have completed initial training on networking and operating systems
- Have introductory knowledge of working within the U.S. government and military
- Have networking knowledge equivalent to Network+ certification
- May have knowledge equivalent to Security+ certification
- Understand Windows OS at a tier 1-2 level
- Understand Windows Active Directory but may not have designed/implemented a custom domain
- May have exposure to PowerShell but it is not guaranteed

## Content Guidelines

- **Self-paced, self-led:** All training content must be completable independently without an instructor
- **Lessons teach, labs reinforce:** Practical hands-on experience comes through labs that reinforce lesson material
- **Labs use open terrain** with Windows and Linux systems; prefer free/open-source applications and services
- **No fluff:** Content is limited to what is required — concise, engaging, and not bloated
- **Primary objective:** Meet the Knowledge, Skills, Abilities, and Tasks (KSATs) for the Cyber Defense Infrastructure Support Specialist work role as defined in `Cyber Defense Infra Supp Spec-KSATs.xlsx`
- **Secondary objective:** Create content that engages learners and has them coming back for more

## Content Conventions

- The order of lessons and labs follows the CDISS Course Outline defined in `CDIH CDISS Course Outlines 2c0d411f014b800fa9daf127100848f2.md`
- Lessons and labs follow a consistent naming pattern: `Lesson <Topic> <uuid>.md` and `LAB <Topic> <uuid>.md`
- Images are referenced by their UUID-based filenames
- References DoD-specific frameworks and instructions (NCDOC, CJCSM, SECNAVINST, RMF)

## License

GPL-3.0
