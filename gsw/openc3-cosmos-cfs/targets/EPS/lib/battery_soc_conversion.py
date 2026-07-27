"""
OpenC3 read-conversion: approximate battery state-of-charge (%) from pack
voltage. Sized for a 3S AA NiMH pack (nominal ~3.6 V). NiMH has a very flat
discharge curve, so this is a coarse gauge -- tune the breakpoints to the
full/empty voltages you actually observe.

File name matches the class (OpenC3 derives BatterySocConversion from
battery_soc_conversion.py). Used from EPS/cmd_tlm/tlm.txt via:
    READ_CONVERSION battery_soc_conversion.py
"""

from openc3.conversions.conversion import Conversion


class BatterySocConversion(Conversion):
    # (pack_voltage, percent) breakpoints, ascending.
    CURVE = [
        (3.30, 0.0),
        (3.45, 10.0),
        (3.55, 25.0),
        (3.60, 50.0),
        (3.75, 75.0),
        (3.90, 90.0),
        (4.05, 100.0),
    ]

    def __init__(self):
        super().__init__()
        self.converted_type = "FLOAT"
        self.converted_bit_size = 32

    def call(self, value, packet, buffer):
        v = packet.read("BATTERYV")
        if v is None:
            return 0.0
        curve = self.CURVE
        if v <= curve[0][0]:
            return 0.0
        if v >= curve[-1][0]:
            return 100.0
        for (v0, p0), (v1, p1) in zip(curve, curve[1:]):
            if v0 <= v <= v1:
                return round(p0 + (p1 - p0) * (v - v0) / (v1 - v0), 1)
        return 0.0
