<!--
  IdslogWidget — an APPEND-ONLY scrolling log for SpaceCop IDS alerts.

  Unlike TEXTBOX (which shows only the current value of the item), this widget
  keeps a running history: every time the bound item changes it pushes a new
  timestamped line to the bottom and auto-scrolls, so the operator sees all
  past alerts in a scrolling console.

  Screen usage:
    WIDGET IDSLOG SPACECOP SPACECOP_REPORT_TLM IDS_MSG [MAX_LINES]
      SETTING RAW width 1000px
      SETTING RAW height 750px

  The 3 required params (target packet item) are what the screen subscribes to;
  the optional 4th param caps how many lines are retained (default 1000).
-->
<template>
  <div ref="log" class="ids-log" :style="computedStyle">
    <div v-for="(line, idx) in lines" :key="idx" class="ids-line">{{ line }}</div>
    <div v-if="lines.length === 0" class="ids-empty">Waiting for IDS alerts…</div>
  </div>
</template>

<script>
// OpenC3 COSMOS 7.x: the Widget base mixin is exported from @openc3/vue-common.
// (On COSMOS 5.x this import was
//  '@openc3/tool-common/src/components/widgets/Widget'. If the generated stub
//  for your version imports it differently, match that line.)
import { Widget } from '@openc3/vue-common/widgets'

export default {
  name: 'IdslogWidget',
  mixins: [Widget],
  // The Widget mixin provides the reactive `value` prop (current value of the
  // bound item), plus `parameters`, `counter`, and `computedStyle`.
  data() {
    return {
      lines: [],
      lastValue: null,
      // Optional 4th screen parameter = max lines to retain.
      maxLines: parseInt(this.parameters?.[3]) || 1000,
    }
  },
  watch: {
    // Append when the alert text changes. Consecutive identical messages are
    // ignored so a re-sent packet doesn't spam the log. If you'd rather log
    // EVERY packet (including repeats), watch `counter` instead of `value`.
    value(newVal) {
      this.appendLine(newVal)
    },
  },
  mounted() {
    // Capture whatever value is already present when the screen opens.
    this.appendLine(this.value)
  },
  methods: {
    appendLine(val) {
      if (val === null || val === undefined) return
      const text = String(val).trim()
      if (text === '' || text === this.lastValue) return
      this.lastValue = text
      const ts = new Date().toISOString().replace('T', ' ').substring(0, 19)
      this.lines.push(`[${ts}] ${text}`)
      if (this.lines.length > this.maxLines) {
        this.lines.splice(0, this.lines.length - this.maxLines)
      }
      // Auto-scroll to the newest line.
      this.$nextTick(() => {
        const el = this.$refs.log
        if (el) el.scrollTop = el.scrollHeight
      })
    },
  },
}
</script>

<style scoped>
.ids-log {
  overflow-y: auto;
  font-family: monospace;
  font-size: 14px;
  line-height: 1.4;
  white-space: pre-wrap;
  word-break: break-word;
  background-color: #0a0a0a;
  color: #00ff64;
  padding: 6px 8px;
  box-sizing: border-box;
}
.ids-line {
  padding: 1px 0;
}
.ids-empty {
  color: #557755;
  font-style: italic;
}
</style>
