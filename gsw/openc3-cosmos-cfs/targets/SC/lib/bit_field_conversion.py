"""
OpenC3 read-conversion: extract a single bit from a wider telemetry item.

Replaces the stock Ruby `bit_field_conversion.rb` for this Python-language
plugin. Used by SC/cmd_tlm/tlm.txt to break the RTS executing/disabled status
bitmap words into per-RTS 0/1 items.

  READ_CONVERSION bit_field_conversion.py 'RTSEXECUTINGSTATUS_1' 0

reads bit 0 of item RTSEXECUTINGSTATUS_1 and returns 0 or 1.
"""

from openc3.conversions.conversion import Conversion


class BitFieldConversion(Conversion):
    def __init__(self, *params):
        super().__init__()
        # OpenC3 derives the conversion class from the *filename*, so the config
        # line should pass only (item_name, bit). A stale or hand-written line
        # that also names the class --
        #   READ_CONVERSION bit_field_conversion.py BitFieldConversion 'ITEM' 0
        # -- arrives here as an extra leading class-name token (3 args, not 2),
        # which is what raises "__init__() takes 3 positional arguments but 4
        # were provided". Drop the stray token so a not-yet-rebuilt plugin still
        # decommutates instead of crash-looping DECOM.
        if len(params) == 3:
            params = params[1:]
        item_name, bit = params
        self.item_name = str(item_name).upper()
        self.bit = int(bit)
        self.converted_type = "UINT"
        self.converted_bit_size = 8

    def call(self, value, packet, buffer):
        raw = packet.read(self.item_name)
        if raw is None:
            return 0
        return (int(raw) >> self.bit) & 0x1
