import unittest

import historical_artifacts as legacy
from galia.history import artifacts as packaged


class ArtifactPackageSurfaceTests(unittest.TestCase):
    def test_shadow_surface_preserves_object_identity(self):
        self.assertIs(packaged.ArtifactReceipt, legacy.ArtifactReceipt)
        self.assertIs(
            packaged.HistoricalArtifactStore,
            legacy.HistoricalArtifactStore,
        )

    def test_shadow_surface_exports_expected_api(self):
        self.assertEqual(
            packaged.__all__,
            [
                "ArtifactReceipt",
                "HistoricalArtifactStore",
            ],
        )


if __name__ == "__main__":
    unittest.main()
