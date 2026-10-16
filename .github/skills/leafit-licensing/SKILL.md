---
name: leafit-licensing
description: 'Use when documenting LeafIT README prerequisites or choosing minimum qualifying Microsoft bundles and separate product entitlements for target workloads, including Azure domain controllers, Nerdio NMe, and Login VSI Hydra.'
---

# LeafIT Licensing

Apply Ponytail and i-have-adhd from [repository instructions](../../copilot-instructions.md). Document what a new operator needs, not what one tenant owns. Query licenses only during an authorized target preflight.

## Workflow

1. Identify the exact feature, product edition, user population, device/OS assumptions, seat count category, and commercial/education/frontline eligibility. Do not confuse Windows 365 Enterprise with Business or other editions.
2. Consult current official Microsoft requirements and product terms, plus the relevant vendor's guidance for NMe or Login VSI Hydra. Determine the required component plans and the minimum bundle within each applicable family. Verify restrictions before preferring Business Premium, frontline, or education offers. Do not equate technical eligibility with cheapest current pricing.
3. Write prerequisites as **Minimum qualifying bundle (required included components)**. Add separate product licenses or add-ons only when the selected scenario actually requires them. Examples illustrate notation, not selected workloads. Prefer the lowest qualifying tier; do not require E5, P2, or Intune Suite simply because the tenant has it. Explicitly label an E-series-only example rather than presenting it as the universal minimum.
4. Link the authoritative source and record when the requirement was checked. Separate bundle prerequisites from product add-ons, Azure consumption, and bootstrap needs such as admin consent, domain verification, permissions, quotas, and access to the Nerdio MCP. Mark unresolved vendor tiers or entitlement details unverified, not assumed.
5. During an authorized read-only target preflight, verify purchased, enabled, available, and assigned service plans privately. Keep actual tenant identifiers, quantities, agreements, approvals, and spending details out of public files and memory. Update only the generic requirements in the README and report any gap without assigning licenses automatically.

Use current official product requirements, [Microsoft Entra licensing](https://learn.microsoft.com/entra/fundamentals/licensing), and the applicable product terms. The [README](../../../README.md) owns the published prerequisite list; this skill owns the method. Do not turn an illustrative product into an environment requirement.