local claims = {
  email_verified: false,
} + std.extVar('claims');

local stringOrNull(v) =
  if v != null && std.type(v) == 'string' && v != '' then v else null;

local firstNonNull(values) =
  if std.length(values) == 0 then null
  else if values[0] != null then values[0]
  else firstNonNull(values[1:]);

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
      // Keep this value strictly string for Kratos schema compatibility.
      name: firstNonNull([
        if 'name' in claims then stringOrNull(claims.name) else null,
        if 'preferred_username' in claims then stringOrNull(claims.preferred_username) else null,
        if 'login' in claims then stringOrNull(claims.login) else null,
        if 'username' in claims then stringOrNull(claims.username) else null,
        if 'nickname' in claims then stringOrNull(claims.nickname) else null,
        if 'sub' in claims then stringOrNull(claims.sub) else null,
        'unknown',
      ]),
      confirmedTerms: true,
    },
  },
}