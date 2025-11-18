# Quick Start Guide

Get up and running with the BIG-IP STIG playbook in 5 minutes.

## Prerequisites

- Ansible installed
- Python 3.6+
- Network access to BIG-IP management interface
- BIG-IP admin credentials

## Installation

### 1. Install F5 Ansible Collection

```bash
ansible-galaxy collection install f5networks.f5_modules
```

### 2. Install Python Dependencies

```bash
pip3 install f5-sdk requests netaddr
```

## Configuration

### 3. Edit Inventory

Edit `inventory.yml` with your BIG-IP details:

```yaml
all:
  children:
    bigip:
      hosts:
        bigip-01:
          ansible_host: 192.168.1.10    # Your BIG-IP IP
          bigip_username: admin          # Your username
          bigip_password: admin          # Your password
```

### 4. Customize Variables (Optional)

Edit `vars/stig_vars.yml` to enable optional features:

```yaml
# Uncomment and configure as needed:
dns_servers:
  - 8.8.8.8
  - 8.8.4.4

ntp_servers:
  - 0.pool.ntp.org
```

## Execution

### 5. Run the Playbook

```bash
ansible-playbook bigip_stig.yml
```

### Check Mode (Dry Run)

```bash
ansible-playbook bigip_stig.yml --check
```

### Verbose Output

```bash
ansible-playbook bigip_stig.yml -v
```

## Verification

### Check Configuration

Login to BIG-IP and verify:

```bash
# SSH to BIG-IP
ssh admin@192.168.1.10

# Check password policy
tmsh list auth password-policy

# Check SSH configuration
tmsh list sys sshd

# Check HTTPD settings
tmsh list sys httpd
```

## Common Issues

### Collection Not Found

```bash
# Reinstall collection
ansible-galaxy collection install f5networks.f5_modules --force
```

### Connection Failed

```bash
# Test connectivity
curl -k https://192.168.1.10

# Verify credentials via SSH
ssh admin@192.168.1.10
```

### Module Errors

```bash
# Install missing Python libraries
pip3 install f5-sdk bigsuds netaddr deepdiff requests
```

## Next Steps

1. Review the full [README.md](README.md) for detailed documentation
2. Customize banner text in `vars/stig_vars.yml`
3. Enable optional configurations (DNS, NTP, SSL ciphers)
4. Set up Ansible Vault for credential security
5. Create UCS backup before production deployment

## Security Best Practices

Before production use:

1. **Create UCS Backup:**
   ```bash
   ssh admin@<bigip-ip>
   tmsh save sys ucs pre-stig-config.ucs
   ```

2. **Use Ansible Vault:**
   ```bash
   ansible-vault encrypt_string 'your_password' --name 'bigip_password'
   ```

3. **Test in Lab:** Always test STIG configurations in non-production first

4. **Review Changes:** Compare before/after configurations

---

For detailed documentation, troubleshooting, and advanced usage, see [README.md](README.md)
