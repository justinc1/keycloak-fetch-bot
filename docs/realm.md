## realm

```
realm

# configure menu, on left
realm_settings
  - DONE
clients
  - DONE
client_scopes
roles
identity_providers
user_federations
authentication

# manage menu, on left
groups
users
sessions
  - ignore
events
  - ignore for now. Maybe Config menu is needed 
import
  - ignore
export
  - ignore
```

## realm_settings
```
# top tabs
General
  - CHECK, just simple attributes
Login
  - CHECK, just simple attributes
Keys
  - QUESTION, keep generated keys or get them from passwordstate
Email
Themes
  - CHECK, just simple attributes (list of theme names)
Localization
Cache
  - ignore, just clear cache command
Tokens
  - CHECK, just simple attributes
Client Registration
  - CHECK, complex objects
Client Policies
  - CHECK, complex objects
Security Defenses
```

## clients
```
# top tabs
Settings
  - CHECK, just simple attributes, many are optional
Keys
  - CHECK, is passwordstate needed
Roles
  - CHECK, I think this is exported, 
Client Scopes
  - CHECK, I think this is exported, 
Mappers
  - CHECK
Scope
  - CHECK
Revocation
  - CHECK, just simple attributes
Sessions
  - ignore, just readonly/status
Offline Access
  - ignore, just readonly/status
Installation
  - ignore, just readonly/status

```

## client_scopes
```
# top tabs
Client Scopes
  - DONE just list of all scopes
Default Client Scopes
  - CHECK are 2 groups exported - "Assigned Default Client Scopes" and "Assigned Optional Client Scopes" 
```

```
# A single client scope
# top tabs
Settings
  - CHECK, just simple attributes
Mappers
  - CHECK, is list, each element - just simple attributes
Scope
  - this is scope-mappings
  - "realm roles"
    - CHECK
  - "client roles"
    - CHECK
```

## roles
```
# top tabs
Realm Roles
  - DONE just list of all roles
Default Roles
  - which roles are default for this realm or for particular client
  - "Realm Default Roles"
    - CHECK
  - "Client Default Roles"
    - CHECK
```

```
# A single role
# top tabs
  - DONE
  - CHECK flat vs composite roles
```

## identity_providers
```
# top tabs
```

## user_federations

```
# top tabs
```

## Authentication
```
# top tabs
Flows
  - CHECK
  - are all exported
Bindings
  - CHECK
  - simple attributes, tells you what is configured for this realm
Required Actions
  - CHECK
  - QUESTION what is this, who needs to obey those "required actions"?
    This can be assigned to user?
Password Policy
  - CHECK, list of policies
OTP Policy
  - CHECK, just simple attributes
WebAuthn Policy
  - CHECK, just simple attributes
WebAuthn Passwordless Policy
  - CHECK, just simple attributes
CIBA Policy
  - CHECK, just simple attributes
```

## groups
```
# top tabs
Groups
  - DONE, list of groups
Default Groups
  - CHECK, are they used?
```

```
# top tabs, for one group
Settings
  - DONE
Attributes
  - DONE
Role Mappings
  - Realm Roles
    - CHECK
  - Client Roles
    - CHECK
Members
  - ignore, just readonly/status
```

## users
```
# top tabs, for one user
Details
  - "Required User Actions" - one from Authentication
Attributes
Credentials
  - passwordstate needed
  - more than one credential possible
Role Mappings
  - CHECK, I hope roles are assigned to groups, not to user.
Groups
  - DONE
Consents
  - ignore
Sessions
  - ignore
```

