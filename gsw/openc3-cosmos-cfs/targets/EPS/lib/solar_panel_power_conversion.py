"""
OpenC3 read-conversion: power (mW) for one solar panel = |V (V) * I (mA)|.
abs() so it reports generated power regardless of the INA219 current-sign
convention.

File name matches the class (SolarPanelPowerConversion). Constructed with the
two source item names. Used from EPS/cmd_tlm/tlm.txt via:
    READ_CONVERSION solar_panel_power_conversion.py RSolarPanelV RSolarPanelMa
"""

from openc3.conversions.conversion import Conversion


class SolarPanelPowerConversion(Conversion):
    def __init__(self, volt_item, curr_item):
        super().__init__()
        self.volt_item = str(volt_item).upper()
        self.curr_item = str(curr_item).upper()
        self.converted_type = "FLOAT"
        self.converted_bit_size = 32

    def call(self, value, packet, buffer):
        v = packet.read(self.volt_item)
        i_ma = packet.read(self.curr_item)
        if v is None or i_ma is None:
            return 0.0
        return round(abs(v * i_ma), 1)  # V * mA = mW
