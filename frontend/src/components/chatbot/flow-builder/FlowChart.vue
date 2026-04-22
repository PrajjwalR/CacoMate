<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted, nextTick, watch } from 'vue'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  MessageSquare,
  MousePointerClick,
  Globe,
  MessageCircle,
  Users,
  Play,
  Flag,
  Plus,
  GitBranch,
  AlertTriangle,
  ZoomIn,
  ZoomOut,
  Maximize2,
  LocateFixed,
  GripVertical
} from 'lucide-vue-next'

interface ButtonConfig {
  id: string
  title: string
  type?: 'reply' | 'url' | 'phone'
  url?: string
  phone_number?: string
}

interface FlowStep {
  id?: string
  step_name: string
  step_order: number
  message: string
  message_type: string
  input_type: string
  buttons: ButtonConfig[]
  conditional_next?: Record<string, string>
  next_step: string
}

const props = defineProps<{
  steps: FlowStep[]
  selectedStepIndex: number | null
  flowName: string
  initialMessage: string
  completionMessage: string
}>()

const emit = defineEmits<{
  selectStep: [index: number]
  addStep: []
  selectFlowSettings: []
  openPreview: []
  connectSteps: [payload: { fromIdx: number; toIdx: number; buttonId?: string }]
}>()

// Refs for measuring positions
const containerRef = ref<HTMLElement | null>(null)
const contentRef = ref<HTMLElement | null>(null)
const stepRefs = ref<Map<number, HTMLElement>>(new Map())
const buttonRefs = ref<Map<string, HTMLElement>>(new Map())
const inputHandleRefs = ref<Map<number, HTMLElement>>(new Map())
const outputHandleRefs = ref<Map<number, HTMLElement>>(new Map())
const startRef = ref<HTMLElement | null>(null)
const endRef = ref<HTMLElement | null>(null)
const svgSize = ref({ width: 1200, height: 2000 })

// Connection lines data
const connections = ref<Array<{
  path: string
  color: string
  label: string
  labelX: number
  labelY: number
  fromStepIdx: number
  toStepIdx: number
  isJump: boolean
}>>([])

const nodeBounds = ref<Array<{ idx: number; x: number; y: number; width: number; height: number }>>([])
const hoveredStepIdx = ref<number | null>(null)
const stepOffsets = ref<Record<number, { x: number; y: number }>>({})
const draggingStepIdx = ref<number | null>(null)
const dragStartX = ref(0)
const dragStartY = ref(0)
const dragOrigin = ref({ x: 0, y: 0 })
const dragDistance = ref(0)
const suppressNextNodeClick = ref(false)

const connectingFromIdx = ref<number | null>(null)
const connectingFromButtonId = ref<string | null>(null)
const connectingMouse = ref({ x: 0, y: 0 })

const layoutStorageKey = computed(() => {
  const flow = (props.flowName || 'untitled-flow').trim().toLowerCase().replace(/\s+/g, '-')
  return `whatomate.flow-layout.${flow}`
})

// Viewport transforms
const zoom = ref(1)
const minZoom = 0.55
const maxZoom = 1.6
const panX = ref(0)
const panY = ref(0)
const isPanning = ref(false)
const panStartX = ref(0)
const panStartY = ref(0)
const panOriginX = ref(0)
const panOriginY = ref(0)

const contentTransform = computed(() => ({
  transform: `translate(${panX.value}px, ${panY.value}px) scale(${zoom.value})`,
  transformOrigin: '0 0',
}))

const minimapWidth = 220
const minimapHeight = 140
const minimapScale = computed(() => {
  const sx = minimapWidth / Math.max(svgSize.value.width, 1)
  const sy = minimapHeight / Math.max(svgSize.value.height, 1)
  return Math.min(sx, sy)
})

const viewportRect = computed(() => {
  if (!containerRef.value) return { x: 0, y: 0, width: 0, height: 0 }
  const viewW = containerRef.value.clientWidth
  const viewH = containerRef.value.clientHeight
  const x = Math.max(0, -panX.value / zoom.value)
  const y = Math.max(0, -panY.value / zoom.value)
  const width = Math.min(svgSize.value.width, viewW / zoom.value)
  const height = Math.min(svgSize.value.height, viewH / zoom.value)
  return { x, y, width, height }
})

const messageTypeIcons: Record<string, any> = {
  text: MessageSquare,
  buttons: MousePointerClick,
  api_fetch: Globe,
  whatsapp_flow: MessageCircle,
  transfer: Users
}

const messageTypeColors: Record<string, string> = {
  text: 'bg-blue-500',
  buttons: 'bg-purple-500',
  api_fetch: 'bg-orange-500',
  whatsapp_flow: 'bg-green-500',
  transfer: 'bg-amber-500'
}

const lineColors = [
  '#8b5cf6', // purple
  '#06b6d4', // cyan
  '#f59e0b', // amber
  '#10b981', // emerald
  '#ec4899', // pink
]

function getStepIcon(messageType: string) {
  return messageTypeIcons[messageType] || MessageSquare
}

function getStepColor(messageType: string) {
  return messageTypeColors[messageType] || 'bg-gray-500'
}

function setStepRef(el: any, idx: number) {
  if (el) stepRefs.value.set(idx, el)
}

function setButtonRef(el: any, stepIdx: number, btnIdx: number) {
  if (el) buttonRefs.value.set(`${stepIdx}-${btnIdx}`, el)
}

function setInputHandleRef(el: any, stepIdx: number) {
  if (el) inputHandleRefs.value.set(stepIdx, el)
}

function setOutputHandleRef(el: any, stepIdx: number) {
  if (el) outputHandleRefs.value.set(stepIdx, el)
}

function getStepOffset(idx: number) {
  return stepOffsets.value[idx] || { x: 0, y: 0 }
}

function getStepWrapperStyle(idx: number) {
  const offset = getStepOffset(idx)
  return {
    transform: `translate(${offset.x}px, ${offset.y}px)`,
  }
}

function loadPersistedLayout() {
  try {
    const raw = localStorage.getItem(layoutStorageKey.value)
    if (!raw) return
    const parsed = JSON.parse(raw) as { stepOffsets?: Record<number, { x: number; y: number }> }
    if (!parsed?.stepOffsets || typeof parsed.stepOffsets !== 'object') return
    stepOffsets.value = parsed.stepOffsets
  } catch {
    // Ignore malformed local storage data.
  }
}

function savePersistedLayout() {
  try {
    localStorage.setItem(layoutStorageKey.value, JSON.stringify({
      stepOffsets: stepOffsets.value
    }))
  } catch {
    // Ignore quota/security errors.
  }
}

// Get button destination
function getButtonDestination(step: FlowStep, stepIdx: number, btn: ButtonConfig, btnIdx: number) {
  const buttonId = btn.id || `btn_${btnIdx + 1}`
  const targetStepName = step.conditional_next?.[buttonId]

  if (targetStepName) {
    const targetIdx = props.steps.findIndex(s => s.step_name === targetStepName)
    if (targetIdx !== -1) {
      return { targetIdx, targetName: targetStepName }
    }
  }

  // Default: next sequential step
  const nextIdx = stepIdx + 1
  if (nextIdx < props.steps.length) {
    return { targetIdx: nextIdx, targetName: props.steps[nextIdx].step_name || `Step ${nextIdx + 1}` }
  }

  return { targetIdx: -1, targetName: 'End' } // -1 = End
}

function getButtonId(btn: ButtonConfig, btnIdx: number): string {
  return btn.id || `btn_${btnIdx + 1}`
}

// Get reply buttons for a step
function getReplyButtons(step: FlowStep) {
  return step.buttons?.filter(b => b.type !== 'url') || []
}

// Check if step has buttons
function hasButtons(step: FlowStep) {
  return step.message_type === 'buttons' && getReplyButtons(step).length > 0
}

// Calculate reachable steps
const reachableSteps = computed(() => {
  const reachable = new Set<number>()
  reachable.add(0) // First step is always reachable

  // BFS to find all reachable steps
  const queue = [0]
  while (queue.length > 0) {
    const currentIdx = queue.shift()!
    const step = props.steps[currentIdx]
    if (!step) continue

    // Transfer steps end the flow - nothing after is reachable from this path
    if (step.message_type === 'transfer') {
      // Transfer ends flow, don't add next step
      continue
    }

    if (hasButtons(step)) {
      // For button steps, only targets of buttons are reachable
      const buttons = getReplyButtons(step)
      buttons.forEach((btn, btnIdx) => {
        const dest = getButtonDestination(step, currentIdx, btn, btnIdx)
        if (dest.targetIdx >= 0 && !reachable.has(dest.targetIdx)) {
          reachable.add(dest.targetIdx)
          queue.push(dest.targetIdx)
        }
      })
    } else {
      // For non-button steps, next step is reachable
      const nextIdx = currentIdx + 1
      if (nextIdx < props.steps.length && !reachable.has(nextIdx)) {
        reachable.add(nextIdx)
        queue.push(nextIdx)
      }
    }
  }

  return reachable
})

// Check if a step is unreachable
function isUnreachable(stepIdx: number): boolean {
  return stepIdx > 0 && !reachableSteps.value.has(stepIdx)
}

// Check if END is reachable (no infinite loop)
const isEndReachable = computed(() => {
  if (props.steps.length === 0) return true

  // Check each reachable step to see if any path leads to END
  for (const stepIdx of reachableSteps.value) {
    const step = props.steps[stepIdx]
    if (!step) continue

    // Transfer steps end the flow (reach "end" via human handoff)
    if (step.message_type === 'transfer') {
      return true
    }

    if (hasButtons(step)) {
      // Check if any button leads to END
      const buttons = getReplyButtons(step)
      for (let btnIdx = 0; btnIdx < buttons.length; btnIdx++) {
        const dest = getButtonDestination(step, stepIdx, buttons[btnIdx], btnIdx)
        if (dest.targetIdx === -1) {
          return true // This button goes to END
        }
      }
    } else {
      // Non-button step: check if it's the last step (goes to END)
      if (stepIdx === props.steps.length - 1) {
        return true
      }
    }
  }

  return false // No path to END found - it's a loop!
})

// Detect steps that are part of a loop (cycle detection)
const stepsInLoop = computed(() => {
  const inLoop = new Set<number>()

  // For each reachable step, check if it can reach itself
  for (const startIdx of reachableSteps.value) {
    const visited = new Set<number>()
    const path: number[] = []

    function dfs(currentIdx: number): boolean {
      if (path.includes(currentIdx)) {
        // Found a cycle - mark all steps in the cycle
        const cycleStart = path.indexOf(currentIdx)
        for (let i = cycleStart; i < path.length; i++) {
          inLoop.add(path[i])
        }
        return true
      }

      if (visited.has(currentIdx)) return false
      visited.add(currentIdx)
      path.push(currentIdx)

      const step = props.steps[currentIdx]
      if (!step || step.message_type === 'transfer') {
        path.pop()
        return false
      }

      if (hasButtons(step)) {
        const buttons = getReplyButtons(step)
        for (let btnIdx = 0; btnIdx < buttons.length; btnIdx++) {
          const dest = getButtonDestination(step, currentIdx, buttons[btnIdx], btnIdx)
          if (dest.targetIdx >= 0) {
            dfs(dest.targetIdx)
          }
        }
      } else {
        const nextIdx = currentIdx + 1
        if (nextIdx < props.steps.length) {
          dfs(nextIdx)
        }
      }

      path.pop()
      return false
    }

    dfs(startIdx)
  }

  return inLoop
})

// Check if a step is part of a loop
function isInLoop(stepIdx: number): boolean {
  return stepsInLoop.value.has(stepIdx)
}

// Calculate and draw connection lines
function updateConnections() {
  if (!containerRef.value || !contentRef.value) return

  const container = containerRef.value
  const content = contentRef.value

  const newConnections: typeof connections.value = []
  const newNodeBounds: typeof nodeBounds.value = []
  let colorIdx = 0

  // Update SVG size based on content
  const contentHeight = container.scrollHeight
  const contentWidth = container.scrollWidth
  svgSize.value = { width: Math.max(1200, contentWidth + 200), height: Math.max(2000, contentHeight) }

  // Helper to compute element position in the untransformed content space.
  // Using offset coordinates prevents misalignment when zoom/pan transforms are active.
  const getPos = (el: HTMLElement) => {
    let left = el.offsetLeft
    let top = el.offsetTop
    let parent = el.offsetParent as HTMLElement | null

    while (parent && parent !== content) {
      left += parent.offsetLeft
      top += parent.offsetTop
      parent = parent.offsetParent as HTMLElement | null
    }

    const width = el.offsetWidth
    const height = el.offsetHeight

    const stepContainer = el.closest('[data-step-index]') as HTMLElement | null
    const stepIdx = stepContainer ? Number(stepContainer.dataset.stepIndex) : null
    const offset = stepIdx !== null && Number.isFinite(stepIdx) ? getStepOffset(stepIdx) : { x: 0, y: 0 }

    return {
      left: left + offset.x,
      right: left + width + offset.x,
      top: top + offset.y,
      bottom: top + height + offset.y,
      centerX: left + width / 2 + offset.x,
      centerY: top + height / 2 + offset.y,
      width,
      height
    }
  }

  props.steps.forEach((step, stepIdx) => {
    // Transfer steps end the flow - no connection to next step
    if (step.message_type === 'transfer') {
      return // Skip drawing connections from transfer steps
    }

    if (!hasButtons(step)) {
      // Non-button step: draw line to configured next step (or sequential fallback)
      const stepEl = stepRefs.value.get(stepIdx)
      let targetIdx = stepIdx + 1
      if (step.next_step) {
        const configuredIdx = props.steps.findIndex(s => s.step_name === step.next_step)
        if (configuredIdx >= 0) targetIdx = configuredIdx
      }
      const nextStepEl = stepRefs.value.get(targetIdx)
      const endEl = endRef.value

      if (stepEl && (nextStepEl || (targetIdx >= props.steps.length && endEl) || (!step.next_step && stepIdx === props.steps.length - 1 && endEl))) {
        const targetEl = nextStepEl || endEl
        if (targetEl) {
          const from = getPos(stepEl)
          const to = getPos(targetEl)

          // Smooth curved line down (n8n-like)
          const midY = from.bottom + (to.top - from.bottom) / 2
          newConnections.push({
            path: `M ${from.centerX} ${from.bottom} C ${from.centerX} ${midY}, ${to.centerX} ${midY}, ${to.centerX} ${to.top}`,
            color: '#9ca3af',
            label: '',
            labelX: 0,
            labelY: 0,
            fromStepIdx: stepIdx,
            toStepIdx: nextStepEl ? targetIdx : -1,
            isJump: targetIdx !== stepIdx + 1
          })
        }
      }
    } else {
      // Button step: draw lines from each button to target
      const replyButtons = getReplyButtons(step)
      const stepEl = stepRefs.value.get(stepIdx)

      // Track how many lines go to each target (for offsetting)
      const targetCounts: Record<number, number> = {}

      replyButtons.forEach((btn, btnIdx) => {
        const buttonEl = buttonRefs.value.get(`${stepIdx}-${btnIdx}`)
        if (!buttonEl || !stepEl) return

        const dest = getButtonDestination(step, stepIdx, btn, btnIdx)
        const targetEl = dest.targetIdx >= 0 ? stepRefs.value.get(dest.targetIdx) : endRef.value

        if (!targetEl) return

        const from = getPos(buttonEl)
        const to = getPos(targetEl)

        // Determine if it's a jump (non-sequential)
        const isJump = dest.targetIdx !== stepIdx + 1

        let path: string
        const color = lineColors[colorIdx % lineColors.length]

        if (isJump && dest.targetIdx >= 0) {
          // Track this target for Y offset
          if (!targetCounts[dest.targetIdx]) targetCounts[dest.targetIdx] = 0
          const targetCount = targetCounts[dest.targetIdx]
          targetCounts[dest.targetIdx]++

          // Curved line around cards for jumps
          const containerWidth = containerRef.value?.clientWidth || 800
          const centerX = containerWidth / 2

          // Calculate X offset - each button gets different offset
          const baseOffset = 220
          const offsetIncrement = 35
          const xOffset = baseOffset + (btnIdx * offsetIncrement)

          // Calculate Y offset for entry point - 40px apart (larger than label height 28px)
          const yEntryOffset = (targetCount - 0.5) * 40

          if (dest.targetIdx > stepIdx) {
            // Forward jump - curve to the RIGHT side
            const rightX = centerX + xOffset
            const entryY = to.centerY + yEntryOffset
            path = `M ${from.centerX} ${from.bottom} ` +
                   `L ${from.centerX} ${from.bottom + 20} ` +
                   `L ${rightX} ${from.bottom + 20} ` +
                   `L ${rightX} ${entryY} ` +
                   `L ${to.right + 10} ${entryY}`
          } else {
            // Backward jump - curve to the LEFT side
            const leftX = centerX - xOffset
            const entryY = to.centerY + yEntryOffset
            path = `M ${from.centerX} ${from.bottom} ` +
                   `L ${from.centerX} ${from.bottom + 20} ` +
                   `L ${leftX} ${from.bottom + 20} ` +
                   `L ${leftX} ${entryY} ` +
                   `L ${to.left - 10} ${entryY}`
          }
          colorIdx++

          // Position label on the VERTICAL portion of the line (not near cards)
          const entryY = to.centerY + yEntryOffset
          const verticalLineX = dest.targetIdx > stepIdx ? centerX + xOffset : centerX - xOffset

          // Label positioned on vertical line, midway between start horizontal and entry point
          const labelX = verticalLineX
          const labelY = (from.bottom + 20 + entryY) / 2

          newConnections.push({
            path,
            color,
            label: `${btn.title || `Btn ${btnIdx + 1}`} → ${dest.targetName}`,
            labelX: labelX,
            labelY: labelY,
            fromStepIdx: stepIdx,
            toStepIdx: dest.targetIdx,
            isJump: true
          })
        } else {
            // Sequential flow - soft curve with slight horizontal offset
          const xOff = (btnIdx - (replyButtons.length - 1) / 2) * 15
            const toX = to.centerX + xOff
            const midY = from.bottom + (to.top - from.bottom) / 2
          path = `M ${from.centerX} ${from.bottom} ` +
                 `C ${from.centerX} ${midY}, ${toX} ${midY}, ${toX} ${to.top}`

          newConnections.push({
            path,
            color: '#9ca3af',
            label: `${btn.title || `Btn ${btnIdx + 1}`} → ${dest.targetName}`,
            labelX: (from.centerX + toX) / 2,
            labelY: midY,
            fromStepIdx: stepIdx,
            toStepIdx: dest.targetIdx >= 0 ? dest.targetIdx : stepIdx + 1,
            isJump: false
          })
        }
      })
    }
  })

  // Start to first step
  if (startRef.value && stepRefs.value.get(0)) {
    const from = getPos(startRef.value)
    const to = getPos(stepRefs.value.get(0)!)

    // Start from bottom of START div (below text), end above first step
    newConnections.unshift({
      path: `M ${from.centerX} ${from.bottom} L ${from.centerX} ${to.top - 15}`,
      color: '#22c55e',
      label: '',
      labelX: 0,
      labelY: 0,
      fromStepIdx: -2, // START
      toStepIdx: 0,
      isJump: false
    })
  }

  // Collect node bounds for minimap
  if (startRef.value) {
    const s = getPos(startRef.value)
    newNodeBounds.push({ idx: -2, x: s.left, y: s.top, width: s.width, height: s.height })
  }
  props.steps.forEach((_, idx) => {
    const el = stepRefs.value.get(idx)
    if (!el) return
    const p = getPos(el)
    newNodeBounds.push({ idx, x: p.left, y: p.top, width: p.width, height: p.height })
  })
  if (endRef.value) {
    const e = getPos(endRef.value)
    newNodeBounds.push({ idx: -1, x: e.left, y: e.top, width: e.width, height: e.height })
  }

  connections.value = newConnections
  nodeBounds.value = newNodeBounds
}

function toContentPoint(clientX: number, clientY: number) {
  if (!containerRef.value) return { x: 0, y: 0 }
  const rect = containerRef.value.getBoundingClientRect()
  return {
    x: (clientX - rect.left - panX.value) / zoom.value,
    y: (clientY - rect.top - panY.value) / zoom.value,
  }
}

function startNodeDrag(stepIdx: number, e: MouseEvent) {
  e.preventDefault()
  e.stopPropagation()
  draggingStepIdx.value = stepIdx
  dragStartX.value = e.clientX
  dragStartY.value = e.clientY
  dragOrigin.value = { ...getStepOffset(stepIdx) }
  dragDistance.value = 0
}

function startConnection(stepIdx: number, e: MouseEvent, buttonId?: string) {
  e.preventDefault()
  e.stopPropagation()
  connectingFromIdx.value = stepIdx
  connectingFromButtonId.value = buttonId ?? null
  connectingMouse.value = toContentPoint(e.clientX, e.clientY)
}

function onGlobalMouseMove(e: MouseEvent) {
  if (draggingStepIdx.value !== null) {
    const dx = (e.clientX - dragStartX.value) / zoom.value
    const dy = (e.clientY - dragStartY.value) / zoom.value
    dragDistance.value = Math.hypot(e.clientX - dragStartX.value, e.clientY - dragStartY.value)
    stepOffsets.value = {
      ...stepOffsets.value,
      [draggingStepIdx.value]: {
        x: Math.round(dragOrigin.value.x + dx),
        y: Math.round(dragOrigin.value.y + dy),
      }
    }
    debouncedUpdate()
  }

  if (connectingFromIdx.value !== null) {
    connectingMouse.value = toContentPoint(e.clientX, e.clientY)
  }
}

function onGlobalMouseUp(e: MouseEvent) {
  if (draggingStepIdx.value !== null) {
    // If user moved enough, treat it as drag and suppress node click on mouse up.
    if (dragDistance.value > 4) {
      suppressNextNodeClick.value = true
      window.setTimeout(() => {
        suppressNextNodeClick.value = false
      }, 0)
    }
    draggingStepIdx.value = null
    dragDistance.value = 0
  }

  if (connectingFromIdx.value !== null) {
    const pointerTarget = document.elementFromPoint(e.clientX, e.clientY) as HTMLElement | null
    const target = (pointerTarget || e.target) as HTMLElement
    const inputHandle = target?.closest('[data-connection-input]') as HTMLElement | null
    const fromIdx = connectingFromIdx.value
    let toIdx: number | null = null

    if (inputHandle) {
      const parsed = Number(inputHandle.dataset.connectionInput)
      if (Number.isFinite(parsed) && parsed >= 0 && parsed !== fromIdx) {
        toIdx = parsed
      }
    }

    // Allow dropping anywhere on the node card (not only tiny input handle)
    if (toIdx === null) {
      const stepNode = target?.closest('[data-step-index]') as HTMLElement | null
      if (stepNode?.dataset.stepIndex) {
        const parsed = Number(stepNode.dataset.stepIndex)
        if (Number.isFinite(parsed) && parsed >= 0 && parsed !== fromIdx) {
          toIdx = parsed
        }
      }
    }

    // Fallback: connect to nearest node center if cursor is close enough
    if (toIdx === null && contentRef.value) {
      const drop = toContentPoint(e.clientX, e.clientY)
      let nearestIdx: number | null = null
      let nearestDist = Number.POSITIVE_INFINITY

      for (const [idx, refEl] of stepRefs.value.entries()) {
        if (idx === fromIdx) continue
        const rect = refEl.getBoundingClientRect()
        const contentRect = contentRef.value.getBoundingClientRect()
        const cx = (rect.left + rect.width / 2 - contentRect.left) / zoom.value
        const cy = (rect.top + rect.height / 2 - contentRect.top) / zoom.value
        const dist = Math.hypot(drop.x - cx, drop.y - cy)
        if (dist < nearestDist) {
          nearestDist = dist
          nearestIdx = idx
        }
      }

      // 80px threshold in content coordinates (scaled naturally by toContentPoint)
      if (nearestIdx !== null && nearestDist <= 80) {
        toIdx = nearestIdx
      }
    }

    if (toIdx !== null) {
      emit('connectSteps', {
        fromIdx,
        toIdx,
        buttonId: connectingFromButtonId.value || undefined
      })
    }
    connectingFromIdx.value = null
    connectingFromButtonId.value = null
  }
}

const draftConnectionPath = computed(() => {
  if (connectingFromIdx.value === null) return ''
  const handleEl = outputHandleRefs.value.get(connectingFromIdx.value)
  if (!handleEl || !contentRef.value) return ''

  const fromRect = handleEl.getBoundingClientRect()
  const contentRect = contentRef.value.getBoundingClientRect()
  const fromX = (fromRect.left + fromRect.width / 2 - contentRect.left) / zoom.value
  const fromY = (fromRect.top + fromRect.height / 2 - contentRect.top) / zoom.value
  const toX = connectingMouse.value.x
  const toY = connectingMouse.value.y
  const c1x = fromX + 80
  const c1y = fromY
  const c2x = toX - 80
  const c2y = toY
  return `M ${fromX} ${fromY} C ${c1x} ${c1y}, ${c2x} ${c2y}, ${toX} ${toY}`
})

// Debounced update
let updateTimeout: number | null = null
function debouncedUpdate() {
  if (updateTimeout) clearTimeout(updateTimeout)
  updateTimeout = window.setTimeout(updateConnections, 50)
}

function setHoveredStep(stepIdx: number | null) {
  hoveredStepIdx.value = stepIdx
}

function isConnectionHighlighted(conn: (typeof connections.value)[number]) {
  if (hoveredStepIdx.value === null) return false
  return conn.fromStepIdx === hoveredStepIdx.value || conn.toStepIdx === hoveredStepIdx.value
}

function onStepCardClick(idx: number) {
  if (suppressNextNodeClick.value || draggingStepIdx.value !== null) return
  emit('selectStep', idx)
}

function zoomIn() {
  zoom.value = Math.min(maxZoom, Number((zoom.value + 0.1).toFixed(2)))
}

function zoomOut() {
  zoom.value = Math.max(minZoom, Number((zoom.value - 0.1).toFixed(2)))
}

function resetView() {
  zoom.value = 1
  panX.value = 0
  panY.value = 0
}

function fitToView() {
  if (!containerRef.value) return
  const rect = containerRef.value.getBoundingClientRect()
  const padding = 80
  const scaleX = (rect.width - padding) / Math.max(svgSize.value.width, 1)
  const scaleY = (rect.height - padding) / Math.max(svgSize.value.height, 1)
  const fitScale = Math.max(minZoom, Math.min(maxZoom, Math.min(scaleX, scaleY)))
  zoom.value = Number(fitScale.toFixed(2))
  panX.value = Math.max(20, (rect.width - svgSize.value.width * zoom.value) / 2)
  panY.value = Math.max(20, (rect.height - svgSize.value.height * zoom.value) / 2)
}

function onCanvasMouseDown(e: MouseEvent) {
  const target = e.target as HTMLElement
  if (target.closest('[data-flow-node="true"]') || target.closest('button') || target.closest('input') || target.closest('textarea')) {
    return
  }
  isPanning.value = true
  panStartX.value = e.clientX
  panStartY.value = e.clientY
  panOriginX.value = panX.value
  panOriginY.value = panY.value
}

function onCanvasMouseMove(e: MouseEvent) {
  if (!isPanning.value) return
  const dx = e.clientX - panStartX.value
  const dy = e.clientY - panStartY.value
  panX.value = panOriginX.value + dx
  panY.value = panOriginY.value + dy
}

function stopPanning() {
  isPanning.value = false
}

function onCanvasWheel(e: WheelEvent) {
  if (!containerRef.value) return
  e.preventDefault()
  const delta = e.deltaY < 0 ? 0.08 : -0.08
  const nextZoom = Math.min(maxZoom, Math.max(minZoom, Number((zoom.value + delta).toFixed(2))))
  if (nextZoom === zoom.value) return

  const rect = containerRef.value.getBoundingClientRect()
  const cursorX = e.clientX - rect.left
  const cursorY = e.clientY - rect.top
  const contentX = (cursorX - panX.value) / zoom.value
  const contentY = (cursorY - panY.value) / zoom.value

  zoom.value = nextZoom
  panX.value = cursorX - contentX * nextZoom
  panY.value = cursorY - contentY * nextZoom
}

watch(() => [props.steps, props.selectedStepIndex], () => {
  nextTick(debouncedUpdate)
}, { deep: true })

watch(stepOffsets, () => {
  savePersistedLayout()
}, { deep: true })

watch(() => props.flowName, () => {
  loadPersistedLayout()
  nextTick(debouncedUpdate)
})

onMounted(() => {
  loadPersistedLayout()
  nextTick(() => setTimeout(updateConnections, 100))
  window.addEventListener('resize', debouncedUpdate)
  window.addEventListener('mouseup', stopPanning)
  window.addEventListener('mousemove', onGlobalMouseMove)
  window.addEventListener('mouseup', onGlobalMouseUp)
  fitToView()
})

onUnmounted(() => {
  window.removeEventListener('resize', debouncedUpdate)
  window.removeEventListener('mouseup', stopPanning)
  window.removeEventListener('mousemove', onGlobalMouseMove)
  window.removeEventListener('mouseup', onGlobalMouseUp)
  if (updateTimeout) clearTimeout(updateTimeout)
})
</script>

<template>
  <div class="h-full flex flex-col bg-[#f6f7fb] dark:bg-[#0b0d12] overflow-hidden">
    <!-- Header -->
    <div class="px-4 py-3 border-b bg-white/90 dark:bg-[#121722] flex items-center justify-between flex-shrink-0 backdrop-blur-sm">
      <div class="flex items-center gap-2">
        <GitBranch class="h-4 w-4 text-muted-foreground" />
        <span class="text-sm font-medium">Flow Diagram</span>
      </div>
      <div class="flex items-center gap-2">
        <Button variant="outline" size="sm" @click="emit('openPreview')">
          <Play class="h-4 w-4 mr-1" />
          Preview
        </Button>
        <Button variant="outline" size="sm" @click="emit('addStep')">
          <Plus class="h-4 w-4 mr-1" />
          Add Step
        </Button>
      </div>
    </div>

    <!-- Flowchart Canvas -->
    <div
      ref="containerRef"
      class="flex-1 overflow-auto relative bg-[radial-gradient(circle_at_1px_1px,rgba(120,130,150,0.22)_1px,transparent_0)] [background-size:20px_20px] dark:bg-[radial-gradient(circle_at_1px_1px,rgba(140,150,170,0.12)_1px,transparent_0)] cursor-grab active:cursor-grabbing"
      @scroll="debouncedUpdate"
      @mousedown="onCanvasMouseDown"
      @mousemove="onCanvasMouseMove"
      @wheel="onCanvasWheel"
    >
      <div ref="contentRef" class="absolute top-0 left-0" :style="contentTransform">
        <!-- SVG Connection Lines - Now with higher z-index -->
        <svg
          class="absolute top-0 left-0 pointer-events-none"
          style="z-index: 5;"
          :width="svgSize.width"
          :height="svgSize.height"
        >
        <defs>
          <marker
            id="arrow-gray"
            markerWidth="8"
            markerHeight="6"
            refX="7"
            refY="3"
            orient="auto"
          >
            <path d="M 0 0 L 8 3 L 0 6 L 2 3 Z" fill="#9ca3af" />
          </marker>
          <marker
            v-for="(color, idx) in lineColors"
            :key="idx"
            :id="`arrow-${idx}`"
            markerWidth="8"
            markerHeight="6"
            refX="7"
            refY="3"
            orient="auto"
          >
            <path d="M 0 0 L 8 3 L 0 6 L 2 3 Z" :fill="color" />
          </marker>
          <marker
            id="arrow-green"
            markerWidth="8"
            markerHeight="6"
            refX="7"
            refY="3"
            orient="auto"
          >
            <path d="M 0 0 L 8 3 L 0 6 L 2 3 Z" fill="#22c55e" />
          </marker>
        </defs>

        <g v-for="(conn, idx) in connections" :key="idx">
          <path
            :d="conn.path"
            fill="none"
            :stroke="isConnectionHighlighted(conn) ? '#4f46e5' : conn.color"
            :stroke-width="isConnectionHighlighted(conn) ? 3.4 : (conn.color === '#9ca3af' ? 1.6 : 2.6)"
            :opacity="hoveredStepIdx !== null && !isConnectionHighlighted(conn) ? 0.28 : 1"
            stroke-linecap="round"
            stroke-linejoin="round"
            :marker-end="conn.color === '#22c55e' ? 'url(#arrow-green)' : conn.color === '#9ca3af' ? 'url(#arrow-gray)' : `url(#arrow-${lineColors.indexOf(conn.color)})`"
          />
          <!-- Label for jump connections - positioned ON the line with solid background -->
          <g v-if="conn.label">
            <!-- White background for visibility -->
            <rect
              :x="conn.labelX - 80"
              :y="conn.labelY - 14"
              width="160"
              height="28"
              rx="14"
              fill="white"
              stroke="#e5e7eb"
              stroke-width="2"
              filter="drop-shadow(0 2px 4px rgba(0,0,0,0.1))"
            />
            <!-- Colored inner background -->
            <rect
              :x="conn.labelX - 77"
              :y="conn.labelY - 11"
              width="154"
              height="22"
              rx="11"
              :fill="conn.color"
            />
            <!-- Label text -->
            <text
              :x="conn.labelX"
              :y="conn.labelY + 5"
              text-anchor="middle"
              fill="white"
              font-size="11"
              font-weight="700"
              style="text-shadow: 0 1px 2px rgba(0,0,0,0.3)"
            >
              {{ conn.label.length > 24 ? conn.label.substring(0, 24) + '…' : conn.label }}
            </text>
          </g>
        </g>
        <path
          v-if="draftConnectionPath"
          :d="draftConnectionPath"
          fill="none"
          stroke="#4f46e5"
          stroke-width="2.4"
          stroke-dasharray="6 5"
          stroke-linecap="round"
          opacity="0.9"
        />
        </svg>

        <!-- Flow Nodes -->
        <div class="relative p-10 flex flex-col items-center min-h-full" style="z-index: 1;">
        <!-- Start Node -->
        <div
          ref="startRef"
          data-flow-node="true"
          class="flex flex-col items-center cursor-pointer group mb-16"
          @mouseenter="setHoveredStep(-2)"
          @mouseleave="setHoveredStep(null)"
          @click="emit('selectFlowSettings')"
        >
          <span class="mb-2 text-xs font-semibold tracking-[0.12em] text-emerald-600">START</span>
          <div class="w-14 h-14 rounded-2xl bg-emerald-500 flex items-center justify-center shadow-md group-hover:shadow-lg transition-all border border-emerald-300/60">
            <Play class="h-6 w-6 text-white" />
          </div>
        </div>

        <!-- Steps -->
        <template v-for="(step, idx) in steps" :key="`step-${idx}`">
          <div :data-step-index="idx" :style="getStepWrapperStyle(idx)">
          <!-- Step Card -->
          <div
            :ref="(el) => setStepRef(el, idx)"
            data-flow-node="true"
            :class="[
              'w-[25rem] rounded-2xl border shadow-sm cursor-pointer transition-all mb-4 relative overflow-hidden',
              isUnreachable(idx)
                ? 'border-red-300 bg-red-50/85 dark:bg-red-900/20 opacity-70'
                : isInLoop(idx)
                  ? 'border-amber-300 bg-amber-50/80 dark:bg-amber-900/20'
                  : selectedStepIndex === idx
                    ? 'border-primary/70 bg-white dark:bg-[#151b26] ring-2 ring-primary/25 shadow-md'
                    : 'border-gray-200/90 dark:border-[#2b3444] bg-white/95 dark:bg-[#151b26] hover:border-primary/35 hover:shadow-md'
            ]"
            @mouseenter="setHoveredStep(idx)"
            @mouseleave="setHoveredStep(null)"
            @click="onStepCardClick(idx)"
          >
            <div
              :ref="(el) => setInputHandleRef(el, idx)"
              :data-connection-input="idx"
              class="absolute -left-2 top-1/2 -translate-y-1/2 w-3.5 h-3.5 rounded-full border-2 border-slate-400 bg-white dark:bg-[#151b26] shadow-sm"
              title="Input handle"
            />
            <div
              :ref="(el) => setOutputHandleRef(el, idx)"
              class="absolute -right-2 top-1/2 -translate-y-1/2 w-3.5 h-3.5 rounded-full border-2 border-indigo-500 bg-white dark:bg-[#151b26] shadow-sm cursor-crosshair"
              title="Drag to connect"
              @mousedown="startConnection(idx, $event)"
            />
            <!-- Loop Warning Badge -->
            <div
              v-if="isInLoop(idx) && !isUnreachable(idx)"
              class="absolute -top-2 left-4 bg-amber-500 text-white text-[10px] font-semibold px-2 py-0.5 rounded-md flex items-center gap-1 shadow-sm z-10"
            >
              <svg class="h-3 w-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M21 12a9 9 0 1 1-6.219-8.56" />
              </svg>
              LOOP
            </div>
            <!-- Unreachable Warning Badge -->
            <div
              v-if="isUnreachable(idx)"
              class="absolute -top-2 left-4 bg-red-500 text-white text-[10px] font-semibold px-2 py-0.5 rounded-md flex items-center gap-1 shadow-sm z-10"
            >
              <AlertTriangle class="h-3 w-3" />
              UNREACHABLE
            </div>

            <!-- Header -->
            <div
              :class="[
                'flex items-center gap-3 px-4 py-3 border-b cursor-move select-none',
                isUnreachable(idx)
                  ? 'bg-red-100/80 dark:bg-red-900/30 border-red-200/80 dark:border-red-800/60'
                  : getStepColor(step.message_type) + ' bg-opacity-10 dark:bg-opacity-20 border-gray-100 dark:border-[#2a3345]'
              ]"
              title="Drag to move node"
              @mousedown="startNodeDrag(idx, $event)"
            >
              <div :class="['w-8 h-8 rounded-md flex items-center justify-center', isUnreachable(idx) ? 'bg-red-400' : getStepColor(step.message_type)]">
                <component :is="isUnreachable(idx) ? AlertTriangle : getStepIcon(step.message_type)" class="h-4 w-4 text-white" />
              </div>
              <span class="font-semibold text-sm flex-1 truncate">{{ step.step_name || `Step ${idx + 1}` }}</span>
              <div class="flex items-center gap-1">
                <Button
                  variant="ghost"
                  size="icon"
                  class="h-6 w-6 cursor-grab active:cursor-grabbing"
                  title="Drag node"
                  @mousedown="startNodeDrag(idx, $event)"
                  @click.stop
                >
                  <GripVertical class="h-3.5 w-3.5 text-muted-foreground" />
                </Button>
                <Badge :variant="isUnreachable(idx) ? 'destructive' : 'secondary'" class="text-[11px] h-5 px-1.5">{{ idx + 1 }}</Badge>
              </div>
            </div>
            <!-- Message -->
            <div class="px-4 py-3">
              <p class="text-xs text-muted-foreground/90 line-clamp-2">{{ step.message || 'No message' }}</p>
            </div>
            <!-- Buttons indicator -->
            <div v-if="hasButtons(step)" class="px-4 pb-3">
              <div class="text-[10px] text-muted-foreground flex items-center gap-1.5">
                <GitBranch class="h-3 w-3" />
                <span>{{ getReplyButtons(step).length }} button{{ getReplyButtons(step).length > 1 ? 's' : '' }} - routes to specific steps</span>
              </div>
            </div>
          </div>

          <!-- Button nodes (shown below step if has buttons) -->
          <div v-if="hasButtons(step)" class="flex gap-2.5 mb-7 flex-wrap justify-center">
            <div
              v-for="(btn, btnIdx) in getReplyButtons(step)"
              :key="btnIdx"
              data-flow-node="true"
              :ref="(el) => setButtonRef(el, idx, btnIdx)"
              :class="[
                'relative px-3.5 py-2 rounded-lg border text-xs font-medium shadow-sm cursor-pointer transition-all min-w-[110px] backdrop-blur-sm',
                getButtonDestination(step, idx, btn, btnIdx).targetIdx !== idx + 1
                  ? 'bg-violet-50/95 dark:bg-violet-900/25 border-violet-300 text-violet-700 dark:text-violet-300 hover:bg-violet-100/90'
                  : 'bg-white/95 dark:bg-[#1b2433] border-gray-300/80 dark:border-[#39465d] text-gray-700 dark:text-gray-300 hover:bg-gray-50'
              ]"
              @click.stop="emit('selectStep', idx)"
            >
              <div class="text-center">
                <div class="font-semibold">{{ btn.title || `Button ${btnIdx + 1}` }}</div>
                <div :class="['text-[10px] mt-0.5', getButtonDestination(step, idx, btn, btnIdx).targetIdx !== idx + 1 ? 'text-violet-500' : 'text-gray-400']">
                  → {{ getButtonDestination(step, idx, btn, btnIdx).targetName }}
                </div>
              </div>
              <div
                class="absolute -right-2 top-1/2 -translate-y-1/2 w-3.5 h-3.5 rounded-full border-2 border-violet-500 bg-white dark:bg-[#151b26] shadow-sm cursor-crosshair"
                title="Drag to connect this button route"
                @mousedown.stop="startConnection(idx, $event, getButtonId(btn, btnIdx))"
              />
            </div>
          </div>

          <!-- Spacer for non-button steps -->
          <div v-else class="h-7"></div>
          </div>
        </template>

        <!-- End Node -->
        <div
          ref="endRef"
          data-flow-node="true"
          class="flex flex-col items-center cursor-pointer group mt-4 relative"
          @mouseenter="setHoveredStep(-1)"
          @mouseleave="setHoveredStep(null)"
          @click="emit('selectFlowSettings')"
        >
          <!-- Completely Unreachable Warning -->
          <div
            v-if="!isEndReachable && steps.length > 0"
            class="absolute -top-3 left-1/2 -translate-x-1/2 bg-red-500 text-white text-[10px] font-bold px-3 py-1 rounded-full flex items-center gap-1 shadow-md z-10 whitespace-nowrap"
          >
            <svg class="h-3 w-3 animate-spin" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M21 12a9 9 0 1 1-6.219-8.56" />
            </svg>
            UNREACHABLE
          </div>
          <!-- Partial Loop Warning (END reachable but some paths loop) -->
          <div
            v-else-if="stepsInLoop.size > 0 && steps.length > 0"
            class="absolute -top-3 left-1/2 -translate-x-1/2 bg-amber-500 text-white text-[10px] font-bold px-3 py-1 rounded-full flex items-center gap-1 shadow-md z-10 whitespace-nowrap"
          >
            <svg class="h-3 w-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M21 12a9 9 0 1 1-6.219-8.56" />
            </svg>
            SOME PATHS LOOP
          </div>
          <div
            :class="[
              'w-14 h-14 rounded-2xl flex items-center justify-center shadow-md transition-all border',
              !isEndReachable && steps.length > 0
                ? 'bg-gray-400 border-gray-300 opacity-55'
                : stepsInLoop.size > 0 && steps.length > 0
                  ? 'bg-amber-500 border-amber-300'
                  : 'bg-rose-500 border-rose-300'
            ]"
          >
            <Flag class="h-6 w-6 text-white" />
          </div>
          <span :class="[
            'mt-2 text-sm font-bold',
            !isEndReachable && steps.length > 0
              ? 'text-gray-400'
              : stepsInLoop.size > 0 && steps.length > 0
                ? 'text-amber-600'
                : 'text-red-600'
          ]">
            {{ !isEndReachable && steps.length > 0 ? 'UNREACHABLE' : 'END' }}
          </span>
          <p v-if="!isEndReachable && steps.length > 0" class="text-xs text-red-600 mt-1 text-center max-w-[200px]">
            Flow has no exit path - will loop forever
          </p>
          <p v-else-if="stepsInLoop.size > 0 && steps.length > 0" class="text-xs text-amber-600 mt-1 text-center max-w-[200px]">
            Some paths never reach END
          </p>
        </div>

        <!-- Empty State -->
        <template v-if="steps.length === 0">
          <div
            class="w-72 py-12 rounded-xl border-2 border-dashed border-gray-300 dark:border-gray-600 flex flex-col items-center justify-center cursor-pointer hover:border-primary hover:bg-primary/5 transition-all my-8"
            @click="emit('addStep')"
          >
            <Plus class="h-10 w-10 text-gray-400 mb-3" />
            <span class="text-sm font-medium text-muted-foreground">Add your first step</span>
          </div>
        </template>
      </div>
      </div>

      <!-- View controls -->
      <div class="absolute right-4 top-4 z-20 flex flex-col gap-2">
        <Button variant="outline" size="icon" class="h-8 w-8 bg-white/90 dark:bg-[#151b26]" @click="zoomIn">
          <ZoomIn class="h-4 w-4" />
        </Button>
        <Button variant="outline" size="icon" class="h-8 w-8 bg-white/90 dark:bg-[#151b26]" @click="zoomOut">
          <ZoomOut class="h-4 w-4" />
        </Button>
        <Button variant="outline" size="icon" class="h-8 w-8 bg-white/90 dark:bg-[#151b26]" @click="fitToView">
          <Maximize2 class="h-4 w-4" />
        </Button>
        <Button variant="outline" size="icon" class="h-8 w-8 bg-white/90 dark:bg-[#151b26]" @click="resetView">
          <LocateFixed class="h-4 w-4" />
        </Button>
        <div class="text-[10px] px-1.5 py-1 rounded border bg-white/90 dark:bg-[#151b26] text-center text-muted-foreground">
          {{ Math.round(zoom * 100) }}%
        </div>
      </div>

      <!-- Minimap -->
      <div class="absolute right-4 bottom-4 z-20 rounded-lg border bg-white/90 dark:bg-[#151b26]/95 shadow-sm p-2 backdrop-blur-sm">
        <div class="text-[10px] text-muted-foreground mb-1.5">Minimap</div>
        <svg :width="minimapWidth" :height="minimapHeight" class="block">
          <rect x="0" y="0" :width="minimapWidth" :height="minimapHeight" fill="transparent" stroke="#e5e7eb" stroke-width="1" />
          <g>
            <rect
              v-for="node in nodeBounds"
              :key="`mini-${node.idx}`"
              :x="node.x * minimapScale"
              :y="node.y * minimapScale"
              :width="Math.max(4, node.width * minimapScale)"
              :height="Math.max(4, node.height * minimapScale)"
              :fill="node.idx < 0 ? '#9ca3af' : (node.idx === selectedStepIndex ? '#4f46e5' : '#94a3b8')"
              rx="2"
              opacity="0.9"
            />
            <rect
              :x="viewportRect.x * minimapScale"
              :y="viewportRect.y * minimapScale"
              :width="Math.max(10, viewportRect.width * minimapScale)"
              :height="Math.max(10, viewportRect.height * minimapScale)"
              fill="none"
              stroke="#4f46e5"
              stroke-width="1.5"
            />
          </g>
        </svg>
      </div>
    </div>
  </div>
</template>
