"""
OpenC3 read-conversion: total generated power (mW) = sum of |V*I| across the 6
real solar panels.

File name matches the class (TotalSolarPowerConversion). Used from
EPS/cmd_tlm/tlm.txt via:
    READ_CONVERSION total_solar_power_conversion.py
"""

from openc3.conversions.conversion import Conversion


class TotalSolarPowerConversion(Conversion):
    PANELS = [
        ("RSOLARPANELV", "RSOLARPANELMA"),
        ("BSOLARPANELV", "BSOLARPANELMA"),
        ("TSOLARPANELV", "TSOLARPANELMA"),
        ("LSOLARPANELV", "LSOLARPANELMA"),
        ("FSOLARPANELV", "FSOLARPANELMA"),
        ("USOLARPANELV", "USOLARPANELMA"),
    ]

    def __init__(self):
        super().__init__()
        self.converted_type = "FLOAT"
        self.converted_bit_size = 32

    def call(self, value, packet, buffer):
        total = 0.0
        for v_item, i_item in self.PANELS:
            v = packet.read(v_item)
            i_ma = packet.read(i_item)
            if v is not None and i_ma is not None:
                total += abs(v * i_ma)
        return round(total, 1)
