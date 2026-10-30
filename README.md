# Claude Code VSX 2.1.313 IOC Check
### Read-only IOC checker for the backdoored Claude Code VS Code extension 2.1.313.

Source: https://phorion.io/blog/offical-claude-code-vsx-compromise/

Checks (nothing is modified, nothing is sent over the network):
  - Installed / cached extension builds of anthropic.claude-code-2.1.313
  - SHA-256 of every installed anthropic.claude-code extension.js
  - ~/.ssh/authorized_keys for the svc-telemetry key (comment and fingerprint)
  - Dropped tunnel keys and scripts (/tmp/.stk_*, ~/.config/.smt, .smtk, ...)
  - macOS LaunchAgent com.apple.sysmond, Linux @reboot cron, Windows SysMon task
  - Running ssh/autossh reverse tunnels and live connections to the C2
  - sshd logs for logins with the attacker key or from localhost

Usage:
  - python3 vsx313.py               # current user
  - sudo python3 vsx313.py          # all users + system logs (Linux/macOS)
  - python3 vsx313.py --deep-logs   # also search macOS unified log (slow)
  - py vsx313.py                    # Windows; from an Administrator prompt for all
                                    # users, SYSTEM tasks and the OpenSSH event log

Exit code: 0 clean, 1 warnings only, 2 indicators found.
