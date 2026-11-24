from .base import REAL_WAIT_HORIZON_SEC, RealSession, RealTarget


def make_target(rp: str, **kw):
    if rp.startswith("vaultwarden"):
        from .vaultwarden import VaultwardenTarget
        return VaultwardenTarget(**kw)
    if rp.startswith("authelia"):
        from .authelia import AutheliaTarget
        return AutheliaTarget(**kw)
    if rp.startswith("keycloak"):
        from .keycloak import KeycloakTarget
        return KeycloakTarget(**kw)
    if rp.startswith("gitea"):
        from .gitea import GiteaTarget
        return GiteaTarget(**kw)
    if rp.startswith("authentik"):
        from .authentik import AuthentikTarget
        return AuthentikTarget(**kw)
    if rp.startswith("kanidm"):
        from .kanidm import KanidmTarget
        return KanidmTarget(**kw)
    if rp.startswith("zitadel"):
        from .zitadel import ZitadelTarget
        return ZitadelTarget(**kw)
    if rp.startswith("privacyidea") or rp.startswith("pi-"):
        from .privacyidea import PrivacyIdeaTarget
        return PrivacyIdeaTarget(**kw)
    if rp.startswith("hanko") or rp.startswith("hk-"):
        from .hanko import HankoTarget
        return HankoTarget(**kw)
    raise ValueError(f"알 수 없는 RP: {rp}")


__all__ = ["REAL_WAIT_HORIZON_SEC", "RealSession", "RealTarget", "make_target"]
