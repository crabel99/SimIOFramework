import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class PendSvServiceIdsTest(unittest.TestCase):
    def test_chip_constructed_named_channel_registry_is_used(self):
        header = (ROOT / "cores/arduino/PendSV.h").read_text()
        implementation = (ROOT / "cores/arduino/PendSV.cpp").read_text()
        adc = (ROOT / "libraries/ADC/src/ADC.cpp").read_text()
        sercom = (ROOT / "cores/arduino/SERCOM.cpp").read_text()

        self.assertIn("struct PendSVChannelMap", header)
        for channel in (
            "Sercom0", "Sercom1", "Sercom2", "Sercom3", "Sercom4", "Sercom5",
            "Sercom6", "Sercom7", "Rtc", "Usb", "Adc", "Dmac", "Aes", "Icm",
            "Pukcc", "Trng", "Gmac", "Phy", "UsbProtocol", "DiscreteInput", "Count",
        ):
            self.assertRegex(header, rf"\b{channel}\b")

        self.assertIn("PendSVChannels::Usb", implementation)
        self.assertIn("PendSVChannels::Adc", adc)
        self.assertIn("PendSVChannels::sercom", sercom)
        self.assertNotRegex(header, r"k(?:TinyUsb|Adc)ServiceId\s*=\s*kMaxServices\s*-")

    def test_optional_sercoms_and_family_peripherals_are_compile_time_gated(self):
        header = (ROOT / "cores/arduino/PendSV.h").read_text()

        for peripheral in ("SERCOM5", "SERCOM6", "SERCOM7", "AES", "ICM", "PUKCC", "TRNG", "GMAC"):
            self.assertIn(f"defined({peripheral})", header)


if __name__ == "__main__":
    unittest.main()
