## Description

This detection identifies AWS Config configuration recorders that have stopped recording. Configuration recorders are critical for capturing resource configuration changes and ensuring compliance with organizational or regulatory policies. Stopped recorders can disrupt continuous monitoring and leave configuration changes untracked.

## Risks

When a configuration recorder stops recording, AWS Config ceases to capture configuration changes for resources in the account. This can lead to gaps in monitoring, making it difficult to detect unauthorized changes, enforce compliance, or troubleshoot operational issues.

Unauthorized or accidental stopping of a configuration recorder may indicate mismanagement or malicious intent, such as an attempt to disable compliance monitoring. Continuous monitoring of the recording status ensures that configuration changes are always tracked and evaluated against defined policies.

## References

- [AWS Config Configuration Recorder](https://docs.aws.amazon.com/config/latest/developerguide/config-concepts.html#config-recorder)
- [AWS CLI Command: stop-configuration-recorder](https://docs.aws.amazon.com/cli/latest/reference/configservice/stop-configuration-recorder.html)
