import unittest

import galia_history_bridge as legacy
from galia.bridge import research as packaged


class ResearchBridgePackageSurfaceTests(unittest.TestCase):
    def test_shadow_surface_preserves_object_identity(self):
        self.assertIs(packaged.ProposedClaim, legacy.ProposedClaim)
        self.assertIs(packaged.GaliaResearchBridge, legacy.GaliaResearchBridge)

    def test_shadow_surface_exports_expected_api(self):
        self.assertEqual(
            packaged.__all__,
            [
                "GaliaResearchBridge",
                "ProposedClaim",
            ],
        )


if __name__ == "__main__":
    unittest.main()
