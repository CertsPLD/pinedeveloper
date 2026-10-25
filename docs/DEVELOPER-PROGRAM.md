# Pine Developer Program

Pine Developer is a developer portal for creating, signing and distributing masOS applications. It follows familiar developer-portal workflows, but it is an independent project and is not an Apple service.

## Features implemented

- Account registration and sign-in, with PBKDF2-SHA-256 password hashing and server-side sessions.
- Team workspace for each account.
- App records and reverse-DNS bundle identifiers.
- App identifiers and device registration for test workflows.
- ECDSA P-256 developer certificates, SHA-256 fingerprints and local PEM private-key download.
- Provisioning-profile records linked to app identifiers, certificates and devices.
- Version/build submission records with status fields.
- Overview dashboard, searchable resource tables and delete operations.
- Separate Cloudflare D1 bindings for developer data and certificate/profile data.

## Cloudflare D1 bindings

The `wrangler.jsonc` file intentionally keeps the supplied databases:

- `developer` binding → database `developer`, ID `410b9b8d-d7ad-4cec-a1c2-e19a3dfa8269`
- `certificates` binding → database `certificates`, ID `e5ae0c02-6743-46de-8567-284980fb9423`

The migration directories are separate so each database receives only its own tables.

Apply the migrations to the remote databases from the project root:

```sh
npx wrangler d1 migrations apply developer --remote
npx wrangler d1 migrations apply certificates --remote
```

Then install dependencies and build:

```sh
npm install
npm run build
```

Configure Cloudflare Pages to use `npm run build` and `dist` as the build output directory. The Pages Functions in `functions/` provide the API.

## Signing certificates

Creating a certificate in the portal uses the browser Web Crypto API to generate an ECDSA P-256 key pair. The public certificate record is stored in the `certificates` D1 database. The private key is downloaded to the user's device and is not uploaded to D1.

**Protect the downloaded private key.** Anyone who obtains it can sign packages as that developer. A valid signature verifies package integrity and key possession; it does not prove that an app is safe.

The exported `.nevcert.json` format is compatible with the masOS package-signing workflow. It is a custom masOS certificate, not an Apple-issued certificate.

## Important scope notes

- Provisioning profiles and distribution submissions are currently management records for masOS; this project does not submit apps to Apple's App Store Connect.
- This portal is not affiliated with or endorsed by Apple.
- For production use, add account recovery, email verification, rate limiting, audit events, organization invitations/roles, certificate revocation checks at package-install time, and independent security review.
