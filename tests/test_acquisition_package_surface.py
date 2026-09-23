import unittest

import historical_acquisition as legacy
from galia.history import acquisition as packaged


class AcquisitionPackageSurfaceTests(unittest.TestCase):
    def test_shadow_surface_preserves_object_identity(self):
        self.assertIs(packaged.AcquisitionReceipt, legacy.AcquisitionReceipt)
        self.assertIs(packaged.record_acquisition_state, legacy.record_acquisition_state)

    def test_shadow_surface_exports_expected_api(self):
        self.assertEqual(
            packaged.__all__,
            [
                "AcquisitionReceipt",
                "AcquisitionState",
                "record_acquisition_state",
            ],
        )


if __name__ == "__main__":
    unittest.main()
