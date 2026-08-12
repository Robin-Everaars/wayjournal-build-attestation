use crate::{DomainRegistration, DomainRegistry, RegistryError, domains, identity};

static IDENTITY_KINDS: &[&str] = &["store.genesis"];
static PROFILE_KINDS: &[&str] = &[
    "profile.alias.add",
    "profile.alias.remove",
    "profile.application.resolve",
    "profile.application.set",
    "profile.capability.add",
    "profile.capability.remove",
    "profile.description.resolve",
    "profile.description.set",
    "profile.display_name.resolve",
    "profile.display_name.set",
    "profile.policy_hint.add",
    "profile.policy_hint.remove",
    "profile.relation.add",
    "profile.relation.remove",
    "profile.remote.add",
    "profile.remote.remove",
];
static CATALOG_KINDS: &[&str] = &[
    "catalog.alias.add",
    "catalog.alias.remove",
    "catalog.default_store.resolve",
    "catalog.default_store.set",
    "catalog.enabled.resolve",
    "catalog.enabled.set",
    "catalog.group.add",
    "catalog.group.remove",
    "catalog.name.resolve",
    "catalog.name.set",
    "catalog.relation.add",
    "catalog.relation.remove",
    "catalog.remote.add",
    "catalog.remote.remove",
];

static BUILTIN_DOMAINS: &[DomainRegistration] = &[
    DomainRegistration::new(
        "wayjournal.identity",
        identity::IDENTITY_SCHEMA_V1,
        IDENTITY_KINDS,
        identity::validate_identity_payload,
    ),
    DomainRegistration::new(
        "wayjournal.profile",
        domains::PROFILE_SCHEMA_V1,
        PROFILE_KINDS,
        domains::validate_profile_payload,
    ),
    DomainRegistration::new(
        "wayjournal.catalog",
        domains::CATALOG_SCHEMA_V1,
        CATALOG_KINDS,
        domains::validate_catalog_payload,
    ),
];

/// Returns the exact compile-time identity/profile/catalog v1 registry.
/// # Errors
/// Returns [`RegistryError`] if a built-in declaration is internally invalid.
pub fn wayjournal_domain_registry() -> Result<DomainRegistry, RegistryError> {
    DomainRegistry::with_builtins(BUILTIN_DOMAINS, &[])
}

/// Composes sealed built-ins with additional compile-time domain declarations.
/// Additional declarations cannot override a built-in domain/schema pair.
/// # Errors
/// Returns [`RegistryError`] for invalid or duplicate declarations.
pub fn wayjournal_domain_registry_with(
    additional: &'static [DomainRegistration],
) -> Result<DomainRegistry, RegistryError> {
    DomainRegistry::with_builtins(BUILTIN_DOMAINS, additional)
}
