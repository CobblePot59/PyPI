# MSuacCalc

`msuaccalc` is a lightweight Python module to decode `userAccountControl` flags used in Active Directory (AD) user objects.

## Installation

```bash
pip install msuaccalc
```

Or with Poetry:

```bash
poetry add msuaccalc
```

## Usage

### As a Python module

```python
import msuaccalc

# Decode UAC value
print(msuaccalc(66048))
# Output: ['NORMAL_ACCOUNT', 'DONT_EXPIRE_PASSWORD']
```

### CLI (after installation)

```bash
msuaccalc 66048
# Output: ['NORMAL_ACCOUNT', 'DONT_EXPIRE_PASSWORD']
```

## Flags Reference

Based on [Microsoft documentation](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties#list-of-property-flags)