ALTER TABLE public.dependency_proxy_secrets
    ADD COLUMN deb_signing_private_key TEXT,
    ADD COLUMN deb_signing_public_key TEXT;
