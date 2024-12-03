# Overview

AWS EC2 Security Groups control inbound and outbound traffic to your EC2 instances. Monitoring changes to these rules is critical to detect and prevent unauthorized access to your VPC or the potential export of sensitive data. Unauthorized changes to ingress and egress rules can be a sign of malicious activity or misconfiguration that could expose your environment to threats.

### Key Reasons for this Detection:

1. **Identifies Security Risks**: Tracks actions such as adding or removing ingress and egress rules to detect potential unauthorized network access or data exfiltration.
2. **Prevents Misuse**: Flags suspicious changes that attackers could use to establish or exploit network access.
3. **Supports Compliance**: Many regulatory standards require strict controls and monitoring of network traffic. This detection helps maintain compliance with such requirements.
4. **Enhances Threat Hunting**: Highlights potential exploitation attempts or defense evasion tactics as described in the MITRE ATT&CK framework.

## What Does this Detection Do?

This detection query monitors CloudTrail log events for the following actions:
- **`AuthorizeSecurityGroupEgress`**: Indicates an outbound rule was added to a security group.
- **`AuthorizeSecurityGroupIngress`**: Indicates an inbound rule was added to a security group.
- **`RevokeSecurityGroupEgress`**: Indicates an outbound rule was removed from a security group.
- **`RevokeSecurityGroupIngress`**: Indicates an inbound rule was removed from a security group.

### Technical Details

The detection query filters logs to exclude events with an error code, ensuring only successful actions are flagged. Results are ordered by `event_time` to prioritize the most recent and potentially relevant events.

## Why is this Important for Security?

### 1. **Preventing Unauthorized Network Changes**
Security group rules define your network boundaries. Unauthorized changes could result in exposing sensitive resources to the public internet or opening unauthorized pathways for data exfiltration.

### 2. **Early Warning System**
Detecting changes to security group rules provides an early warning for potential exploitation or network abuse. For example:
- An attacker might add an ingress rule to allow remote access for lateral movement.
- A compromised account could add an egress rule to facilitate data exfiltration.

### 3. **Aligning with Best Practices**
AWS Security Best Practices recommend strict control over security group rules. Regular monitoring ensures that changes align with intended configurations and permissions.

### 4. **Visibility for Incident Response**
Security group rule changes are critical to understanding how an attack may have occurred or how data may have been exfiltrated during a security incident.

