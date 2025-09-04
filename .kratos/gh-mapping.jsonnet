local claims = {
  email_verified: false,
} + std.extVar('claims');

local splitName(fullName) = 
  local parts = std.split(fullName, ' ');
  if std.length(parts) > 1 then
    {
      first: parts[0],
      last: std.join(' ', parts[1:])
    }
  else
    {
      first: fullName,
      last: ''
    };

{
  identity: {
    traits: {
      // Allowing unverified email addresses enables account
      // enumeration attacks, especially if the value is used for
      // e.g. verification or as a password login identifier.
      //
      // Therefore we only return the email if it (a) exists and (b) is marked verified
      // by GitHub.
      [if 'email' in claims && claims.email_verified then 'email' else null]: claims.email,
      name: splitName(claims.name),
      confirmedTerms: true,
    },
  },
}