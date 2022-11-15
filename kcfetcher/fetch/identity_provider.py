import logging
import sys
from kcfetcher.fetch import GenericFetch

logger = logging.getLogger(__name__)


class IdentityProviderFetch(GenericFetch):
    def _get_data(self):
        kc = self.kc.build(self.resource_name, self.realm)
        kc_objects = self.all(kc)

        for kc_object in kc_objects:
            # remove internalId
            kc_object.pop("internalId")

            # Show error if provider type is not SAML.
            # Also openid v1 seems to work, but we didn't check all attributes.
            tested_provider_ids = ["saml"]
            if kc_object['providerId'] not in tested_provider_ids:
                logger.error(f"Identity provider providerId={kc_object['providerId']} is not sufficiently tested, realm={self.realm} alias={kc_object['alias']}")
                sys.exit(1)

        return kc_objects
