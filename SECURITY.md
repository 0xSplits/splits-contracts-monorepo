# Security

Ensuring the security of the Splits Ecosystem is our utmost priority. We have invested a significant amount of time and money into 
designing, testing, and auditing our contracts to maximize their safety and reliability. However, we recognize security is an ongoing process.
If you believe you have found a security vulnerability, please read the following guidelines and report it to us.

## Bug Bounty

### Overview

Starting on September 1, 2024, the [Splits contracts monorepo](https://github.com/0xSplits/splits-contracts-monorepo) is subject to
the Splits Contracts Monorepo Bug Bounty (the "Program") to incentivize responsible bug disclosure.

We are limiting the scope of the Program to [critical and high severity bugs](https://immunefi.com/immunefi-vulnerability-severity-classification-system-v2-3/), and are offering a reward of up to
$25,000. Happy hunting!

### Scope

The scope of the Program is limited to bugs that result in the draining of user funds.

The Program does NOT cover the following:

- Code located in [test](./test) or [script](./script) directories.
- External code in `node_modules`, except for code that is explicitly used by a deployed contract located in the
  [src](./src) directory.
- Contract deployments on test networks, such as Sepolia.
- Bugs in third-party contracts or platforms interacting with our contracts.
- Previously reported or discovered vulnerabilities in contracts built by third parties on our contracts.
- Bugs that have already been reported.

Vulnerabilities contingent upon the occurrence of any of the following also are outside the scope of this Program:

- Front-end bugs (clickjacking etc.)
- DDoS attacks
- Spamming
- Phishing
- Social engineering attacks
- Private key leaks
- Automated tools (Github Actions, etc.)
- Compromise or misuse of third party systems or services

### Rewards

Rewards will be allocated based on the severity of the bug disclosed and will be evaluated and rewarded at the
discretion of the Splits team. For critical bugs that lead to any loss of user funds, rewards of up to $25,000
will be granted. Lower severity bugs will be rewarded at the discretion of the team.

### Disclosure

Any vulnerability or bug discovered must be reported only to the following email:
[security@splits.org](mailto:security@splits.org).

The vulnerability must not be disclosed publicly or to any other person, entity or email address before Splits has
been notified, has fixed the issue, and has granted permission for public disclosure. In addition, disclosure must be
made within 24 hours following discovery of the vulnerability.

A detailed report of a vulnerability increases the likelihood of a reward and may increase the reward amount. Please
provide as much information about the vulnerability as possible, including:

- The conditions on which reproducing the bug is contingent.
- The steps needed to reproduce the bug or, preferably, a proof of concept.
- The potential implications of the vulnerability being abused.

Anyone who reports a unique, previously-unreported vulnerability that results in a change to the code or a configuration
change and who keeps such vulnerability confidential until it has been resolved by our engineers will be recognized
publicly for their contribution if they so choose.

### Eligibility

To qualify for a reward under this Program, you must adhere to the following criteria:

- Identify a previously unreported, non-public vulnerability that could result in the loss or freeze of any user funds
  in our contracts (but not on any third-party platform interacting with our contracts) and that is within the scope of this
  Program.
- The vulnerability must be distinct from the issues covered in the previous audits.
- Be the first to report the unique vulnerability to [security@splits.org](mailto:security@splits.org) in accordance
  with the disclosure requirements specified above. If multiple similar vulnerabilities are reported within a 24-hour
  timeframe, rewards will be split at the discretion of the Splits team.
- Provide sufficient information to enable our engineers to reproduce and fix the vulnerability.
- Not engage in any unlawful conduct when disclosing the bug, including through threats, demands, or any other coercive
  tactics.
- Avoid exploiting the vulnerability in any manner, such as making it public or profiting from it (aside from the reward
  offered under this Program).
- Make a genuine effort to prevent privacy violations, data destruction, and any interruption or degradation of our services.
- Submit only one vulnerability per submission, unless chaining vulnerabilities is necessary to demonstrate the impact
  of any of them.
- Do not submit a vulnerability that stems from an underlying issue for which a reward has already been paid under this
  Program.
- You must not be a current or former employee, vendor, or contractor, or an employee of any of our
  vendors or contractors.
- You must not be subject to US sanctions or reside in a US-embargoed country.
- Be at least 18 years old, or if younger, submit the vulnerability with the consent of a parent or guardian.

### Other Terms

By submitting your report, you grant Splits Protocols, Inc. and all rights, including intellectual property rights, needed to
validate, mitigate, and disclose the vulnerability. All reward decisions, including eligibility for and amounts of the
rewards and the manner in which such rewards will be paid, are made at our sole discretion.

The terms and conditions of this Program may be altered at any time.

### Acknowledgements

This security policy was inspired by and adapted from Sablier Labs.
