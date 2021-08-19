## Simple jwt implementation loopholes

1. The JWT can only be invalidated when it expires. A major limitation to this is: a user can login, then decide to logout immediately, but the user’s JWT remains valid until the expiration time is reached.
2. The JWT might be hijacked and used by a hacker without the user doing anything about it until the token expires.
3. The user will need to re-login after the token expires, thereby leading to a poor user experience.

## Solution
1. Using a persistence storage layer to store JWT metadata. This will enable us to invalidate a JWT the very second a the user logs out, thereby improving security.
2. Using the concept of a refresh token to generate a new access token, in the event that the access token expired, thereby improving the user experience.

