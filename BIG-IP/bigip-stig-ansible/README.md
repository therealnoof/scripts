# F5 BIG-IP STIG Configuration Ansible Playbook

Ansible playbook to apply Security Technical Implementation Guide (STIG) and Security Requirements Guide (SRG) hardening to F5 BIG-IP systems.

## Overview

This playbook automates the configuration of F5 BIG-IP systems to meet DISA STIG compliance requirements. It applies security hardening across multiple areas including SSH, HTTPD, password policies, encryption protocols, and system settings.

**Original Script:** [bigipstig.sh](https://github.com/therealnoof/scripts/blob/master/BIG-IP/bigipstig.sh)
**Authors:** Michael Coleman (M.Coleman@F5.com), Modified by R. Eastman (r.eastman@f5.com)
**Converted to Ansible:** 2025

## Features

### Security Configurations Applied

1. **SSH Hardening**
   - Protocol 2 only
   - Inactivity timeout (900 seconds)
   - Maximum authentication attempts (3)
   - Approved ciphers and MACs
   - Login grace time (60 seconds)
   - DoD/Federal compliance banner

2. **HTTPD/GUI Security**
   - SSL/TLS cipher restrictions
   - Protocol restrictions (disable SSLv2, SSLv3, TLSv1)
   - HTTP to HTTPS redirect
   - Session timeout (900 seconds)
   - Maximum clients (10)
   - Security banner display

3. **Password Policy Enforcement**
   - Minimum length: 8 characters
   - Complexity requirements (2 of each: uppercase, lowercase, numeric, special)
   - Maximum duration: 90 days
   - Minimum duration: 1 day
   - Password memory: 3 previous passwords
   - Maximum login failures: 3
   - Expiration warning: 7 days

4. **Logging Configuration**
   - TMM logging (informational level)
   - SSL logging (informational level)
   - MCPD audit logging (enabled)
   - MCPD log level (notice)

5. **System Configuration**
   - NTP timezone (UTC)
   - DNS caching (enabled)
   - SNMP community removal (comm-public)
   - Software auto-update disabled
   - GUI preferences optimization

6. **Optional Configurations**
   - DNS servers
   - NTP servers
   - DNS search domains
   - SSL profile cipher customization
   - Management routes

## Requirements

### Software Requirements

- **Ansible:** 2.9 or later
- **Python:** 3.6 or later
- **F5 Ansible Collection:** f5networks.f5_modules (>= 1.25.0)
- **Python Libraries:**
  - f5-sdk
  - bigsuds
  - netaddr
  - deepdiff
  - requests

### BIG-IP Requirements

- **F5 BIG-IP:** Version 12.x or later
- **Management Access:** HTTPS (port 443)
- **Credentials:** Administrative privileges required
- **Network Access:** Ansible control node must reach BIG-IP management interface

## Installation

### 1. Clone or Download Repository

```bash
cd /path/to/your/ansible/projects
# If you have this as a git repo:
# git clone <your-repo-url>
# cd bigip-stig-ansible
```

### 2. Install Ansible Collections

```bash
ansible-galaxy collection install -r requirements.yml
```

### 3. Install Python Dependencies

```bash
pip3 install f5-sdk bigsuds netaddr deepdiff requests
```

### 4. Configure Inventory

Edit `inventory.yml` with your BIG-IP device details:

```yaml
all:
  children:
    bigip:
      hosts:
        bigip-01:
          ansible_host: 192.168.1.10
          bigip_username: admin
          bigip_password: admin
```

**Security Best Practice:** Use Ansible Vault to encrypt credentials:

```bash
ansible-vault encrypt_string 'your_password' --name 'bigip_password'
```

### 5. Customize Variables (Optional)

Edit `vars/stig_vars.yml` to customize:
- Banner text
- DNS servers
- NTP servers
- SSL cipher suites
- Search domains

## Usage

### Basic Execution

Run the playbook against all BIG-IP devices in inventory:

```bash
ansible-playbook bigip_stig.yml
```

### Target Specific Host

```bash
ansible-playbook bigip_stig.yml --limit bigip-01
```

### Use Different Inventory

```bash
ansible-playbook -i custom_inventory.yml bigip_stig.yml
```

### Dry Run (Check Mode)

```bash
ansible-playbook bigip_stig.yml --check
```

### Verbose Output

```bash
ansible-playbook bigip_stig.yml -v    # verbose
ansible-playbook bigip_stig.yml -vv   # more verbose
ansible-playbook bigip_stig.yml -vvv  # very verbose (debug)
```

### With Vault-Encrypted Credentials

```bash
ansible-playbook bigip_stig.yml --ask-vault-pass
```

## Project Structure

```
bigip-stig-ansible/
├── README.md                 # This file
├── ansible.cfg               # Ansible configuration
├── requirements.yml          # Ansible collection requirements
├── inventory.yml             # BIG-IP device inventory
├── bigip_stig.yml           # Main playbook
├── vars/
│   └── stig_vars.yml        # Configuration variables
└── group_vars/              # (optional) Group-specific variables
    └── bigip.yml
```

## Configuration Details

### Provider Configuration

The playbook uses the F5 provider pattern for authentication:

```yaml
provider:
  server: "{{ ansible_host }}"
  user: "{{ bigip_username }}"
  password: "{{ bigip_password }}"
  validate_certs: no
  server_port: 443
```

### Task Organization

Tasks are organized by functional area:
1. SSH Configuration
2. System Configuration
3. GUI Configuration
4. HTTPD Configuration
5. Software Update Configuration
6. SNMP Configuration
7. Logging Configuration
8. Password Policy Configuration
9. Optional Configurations

### Idempotency

The playbook is designed to be idempotent - running it multiple times will produce the same result without causing errors or duplicate configurations.

## Verification

After running the playbook, verify configurations:

### Via TMSH (on BIG-IP)

```bash
# SSH settings
tmsh list sys sshd

# Password policy
tmsh list auth password-policy

# HTTPD settings
tmsh list sys httpd

# GUI settings
tmsh list sys global-settings

# Check banner
tmsh list sys sshd banner-text
```

### Via GUI

1. Navigate to **System > Configuration**
2. Check **Device > General** for banner
3. Review **Users > Authentication** for password policy
4. Verify **System > Logs** for logging configuration

## Troubleshooting

### Connection Issues

**Problem:** Cannot connect to BIG-IP

**Solutions:**
- Verify network connectivity: `ping <bigip-ip>`
- Check HTTPS access: `curl -k https://<bigip-ip>`
- Verify credentials
- Check firewall rules

### Module Not Found

**Problem:** `bigip_command` module not found

**Solutions:**
```bash
# Reinstall F5 collection
ansible-galaxy collection install f5networks.f5_modules --force

# Verify installation
ansible-galaxy collection list | grep f5
```

### Authentication Failures

**Problem:** Authentication failed

**Solutions:**
- Verify credentials in inventory
- Check user permissions (admin role required)
- Try manual login via GUI/SSH
- Check for account lockouts

### Command Failures

**Problem:** Individual TMSH commands fail

**Solutions:**
- Enable verbose mode: `ansible-playbook bigip_stig.yml -vvv`
- Check BIG-IP logs: `/var/log/ltm`
- Verify BIG-IP version compatibility
- Review task output for specific errors

### SSL/Certificate Warnings

**Problem:** SSL certificate validation warnings

**Solution:** This is expected. The playbook uses `validate_certs: no` for self-signed certificates. In production, consider using proper certificates.

## Security Considerations

### Credential Management

1. **Never commit plaintext passwords** to version control
2. Use **Ansible Vault** for sensitive data:
   ```bash
   ansible-vault create vars/vault.yml
   ansible-vault encrypt_string 'password' --name 'bigip_password'
   ```
3. Consider using **environment variables** or external secrets management

### Network Security

1. Restrict Ansible control node access to management networks
2. Use **jump hosts/bastion** for production environments
3. Enable **audit logging** on Ansible control node
4. Use **SSH keys** where possible instead of passwords

### Change Management

1. **Test in non-production** environments first
2. Review configuration changes with security team
3. Document deviations from STIG requirements (with justification)
4. Maintain configuration backups before applying changes
5. Use **UCS archives** for BIG-IP backups:
   ```bash
   tmsh save sys ucs pre-stig-backup.ucs
   ```

## Customization

### Modifying Banner Text

Edit `vars/stig_vars.yml`:

```yaml
stig_banner_text: "Your custom banner text here"
```

### Enabling Optional Configurations

Uncomment and configure in `vars/stig_vars.yml`:

```yaml
dns_servers:
  - 8.8.8.8
  - 8.8.4.4

ntp_servers:
  - 0.pool.ntp.org
  - 1.pool.ntp.org
```

### Adding Custom Tasks

Add tasks to `bigip_stig.yml`:

```yaml
- name: Custom configuration task
  bigip_command:
    provider: "{{ provider }}"
    commands:
      - modify sys <your-tmsh-command>
  delegate_to: localhost
```

## Compliance Mapping

This playbook addresses the following STIG categories:

- **CAT I (High):** Critical security controls
  - SSH protocol restrictions
  - Strong encryption requirements
  - Session timeout enforcement

- **CAT II (Medium):** Important security controls
  - Password complexity
  - Banner implementation
  - Logging configuration

- **CAT III (Low):** Advisory security controls
  - GUI preferences
  - Auto-update settings

## References

- [DISA STIGs](https://public.cyber.mil/stigs/)
- [F5 Ansible Documentation](https://clouddocs.f5.com/products/orchestration/ansible/devel/)
- [F5 BIG-IP STIG Guide](https://www.f5.com/pdf/deployment-guides/f5-stig-implementation-guide.pdf)
- [Original Bash Script](https://github.com/therealnoof/scripts/blob/master/BIG-IP/bigipstig.sh)

## Contributing

To contribute improvements:

1. Test changes in lab environment
2. Document all modifications
3. Update this README with new features
4. Follow Ansible best practices
5. Submit pull requests with detailed descriptions

## License

This playbook is provided as-is for demonstration and automation purposes. Test thoroughly before production use.

## Support

For issues or questions:
- Review F5 Ansible documentation
- Check BIG-IP system logs
- Contact your F5 representative
- Review DISA STIG documentation

## Changelog

### Version 1.0.0 (2025)
- Initial conversion from bash script to Ansible playbook
- Added modular task organization
- Implemented variable-based configuration
- Added comprehensive documentation
- Included optional configuration support
- Added security best practices

---

**Note:** Always test STIG configurations in a non-production environment before applying to production systems. Some settings may impact application functionality or administrative workflows.
