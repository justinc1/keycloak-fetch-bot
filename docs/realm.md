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
check if they are really needed - used by customer.

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
  - DONE is exported, is list, each element - just simple attributes
Scope
  - this is scope-mappings
  - "realm roles"
    - TODO - use GET /{realm}/client-scopes/{id}/scope-mappings/realm
  - "client roles"
    - ignore
```

## roles
```
# top tabs
Realm Roles
  - DONE just list of all roles
Default Roles
  - DONE, is just a GUI trick
```

```
# A single role
# top tabs
  - DONE
  - TODO flat vs composite roles
    - composite roles, export included roles
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
  - WIP, list of groups
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
  - CHECK, are group-role mappings used?
  - Realm Roles
    - TODO
  - Client Roles
    - TODO - try to avoid, use "Realm Roles" - client roles are sort of old-way, deprecated.
Members
  - ignore, just readonly/status
```

QUESTION, exported group.json has '"subGroups": []'. Where in GUI is this?

## users
```
# top tabs, for one user
Details
  - DONE
  - "Required User Actions" - those come from Authentication
Attributes
  - DONE
Credentials
  - QUESTION is passwordstate needed - is there a password for each human user?
    Likely not - user does password reset.
  - more than one credential possible
Role Mappings
  - CHECK, can we ignore this? - I hope roles are assigned to groups, not to user.
Groups
  - DONE
Consents
  - ignore
Sessions
  - ignore
```

## extra

preprocessor - auth flow - some jar files
 - things just crash without that jar file
