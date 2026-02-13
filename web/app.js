/* ========================================================
   Vulnerability Agent – Frontend Application
   ======================================================== */

// ── DOM References ──────────────────────────────────────
const statusIndicator = document.getElementById("status-indicator");
const statusText = document.getElementById("status-text");
const connectButton = document.getElementById("connect-button");
const disconnectButton = document.getElementById("disconnect-button");
const gatewayInput = document.getElementById("gateway-url");
const chatForm = document.getElementById("chat-form");
const chatInput = document.getElementById("chat-input");
const messagesArea = document.getElementById("messages");
const startAudioButton = document.getElementById("start-audio");
const stopAudioButton = document.getElementById("stop-audio");
const audioStatusText = document.getElementById("audio-status");
const audioLevelBar = document.getElementById("audio-level-bar");
const voiceOrb = document.getElementById("voice-orb");
const voiceSessionOverlay = document.getElementById("voice-session-overlay");
const voiceSessionLabel = document.getElementById("voice-session-label");
const voiceOrbLargePath = document.getElementById("voice-orb-large-path");
const voiceSessionCloseButton = document.getElementById("voice-session-close");
const activityFeed = document.getElementById("activity-feed");
const clearActivityButton = document.getElementById("clear-activity");
const pingLatencyText = document.getElementById("ping-latency");
const reconnectCountText = document.getElementById("reconnect-count");
const toastContainer = document.getElementById("toast-container");
const sendButton = chatForm.querySelector('button[type="submit"]');
const activityRequestIdText = document.getElementById("activity-request-id");
const activityProgressText = document.getElementById("activity-progress");
const activityStepText = document.getElementById("activity-step");

// ── Audio Detection Constants ───────────────────────────
const RMS_SPEECH_THRESHOLD = 0.025;
const RMS_SILENCE_THRESHOLD = 0.012;
const RMS_SMOOTHING = 0.2;
const PAUSE_TRIGGER_MS = 650;
const MAX_RENDERED_MESSAGES = 200;
const HEALTH_PING_INTERVAL_MS = 30000;
const GATEWAY_URL_STORAGE_KEY = "vuln_agent_gateway_url";
const GREETING_UNLOCK_TIMEOUT_MS = 20000;

// ── State ───────────────────────────────────────────────
let socket = null;
let audioContext = null;
let mediaStream = null;
let processor = null;
let currentPlaybackSource = null;
let lastSpeechTimestamp = 0;
let smoothedRms = 0;
let mode = "idle";
let thinkingBubble = null;
let activityCount = 0;
let isLiveSessionActive = false;
let hasSocketError = false;
let liveTextBubble = null;
let socketGeneration = 0;
let healthPingIntervalId = null;
let reconnectCount = 0;
let hasEverConnected = false;
let manualDisconnectRequested = false;
let isRequestInFlight = false;
let audioCaptureNode = null;
let currentActivityRequestId = null;
let awaitingAgentGreeting = false;
let greetingUnlockTimerId = null;
let hasReceivedGreetingAudio = false;
let overlayRafId = null;
let orbEnergy = 0;
let greetingFallbackUtterance = null;
let didAttemptGreetingSpeechFallback = false;
let playbackQueue = [];
let isPlaybackQueueDraining = false;
let playbackIdleTimerId = null;
let standalonePlaybackContext = null;

// ── Utility Functions ───────────────────────────────────
function escapeHtml(str) {
  const el = document.createElement("div");
  el.textContent = str;
  return el.innerHTML;
}

function formatTime() {
  return new Date().toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function renderIcons(root) {
  if (typeof lucide !== "undefined") {
    lucide.createIcons({ nodes: root ? [root] : undefined });
  }
}

function showToast(message, kind = "info", timeoutMs = 4000) {
  if (!toastContainer) return;
  const toast = document.createElement("div");
  toast.className = `toast toast-${kind}`;
  toast.textContent = message;
  toastContainer.appendChild(toast);
  window.setTimeout(() => {
    toast.remove();
  }, timeoutMs);
}

function extractJapaneseText(input) {
  const raw = String(input || "");
  const filtered = raw.replace(/[^\u3040-\u30FF\u3400-\u9FFF\u3000-\u303F\uFF00-\uFFEF0-9０-９A-Za-z\s。、，．・！？「」（）【】『』ー〜\-]/g, "");
  const removedAsciiWords = filtered.replace(/[A-Za-z][A-Za-z0-9'":;,.!?()\-]*/g, "");
  return removedAsciiWords.trim();
}

function pruneMessages() {
  const messages = messagesArea.querySelectorAll(".message");
  if (messages.length <= MAX_RENDERED_MESSAGES) return;
  let toRemove = messages.length - MAX_RENDERED_MESSAGES;
  for (const node of messages) {
    if (toRemove <= 0) break;
    if (node === liveTextBubble) liveTextBubble = null;
    if (node === thinkingBubble) thinkingBubble = null;
    node.remove();
    toRemove--;
  }
}

function setRequestInFlight(nextState) {
  isRequestInFlight = nextState;
  sendButton.disabled = nextState || !socket || socket.readyState !== WebSocket.OPEN;
  chatInput.disabled = nextState || !socket || socket.readyState !== WebSocket.OPEN;
}

function updateHealthMetrics(latencyMs = null) {
  if (pingLatencyText) {
    pingLatencyText.textContent = latencyMs == null ? "Ping: -- ms" : `Ping: ${latencyMs} ms`;
  }
  if (reconnectCountText) {
    reconnectCountText.textContent = `Reconnects: ${reconnectCount}`;
  }
}

function formatRequestLabel(requestId) {
  if (!requestId) return "-";
  return requestId.length > 14 ? requestId.slice(0, 14) : requestId;
}

function updateActivityHeader(requestId, progress, stepLabel) {
  if (activityRequestIdText) {
    activityRequestIdText.textContent = `Request: ${formatRequestLabel(requestId)}`;
  }

  const total = Number(progress?.total_tool_calls || 0);
  const completed = Number(progress?.completed_tool_calls || 0);
  if (activityProgressText) {
    activityProgressText.textContent = `Progress: ${completed}/${total}`;
  }

  if (activityStepText) {
    activityStepText.textContent = `Step: ${stepLabel || "Idle"}`;
  }
}

function parseGatewayBaseHttpUrl(rawWsUrl) {
  try {
    const parsed = new URL(rawWsUrl);
    if (parsed.protocol !== "ws:" && parsed.protocol !== "wss:") return null;
    const nextProtocol = parsed.protocol === "wss:" ? "https:" : "http:";
    return `${nextProtocol}//${parsed.host}`;
  } catch {
    return null;
  }
}

async function runHealthPing() {
  const wsUrl = gatewayInput.value.trim();
  const baseUrl = parseGatewayBaseHttpUrl(wsUrl);
  if (!baseUrl) {
    updateHealthMetrics(null);
    return;
  }
  const startedAt = performance.now();
  try {
    const response = await fetch(`${baseUrl}/ping`, {
      method: "GET",
      cache: "no-store",
    });
    if (!response.ok) {
      updateHealthMetrics(null);
      return;
    }
    const latency = Math.max(1, Math.round(performance.now() - startedAt));
    updateHealthMetrics(latency);
  } catch {
    updateHealthMetrics(null);
  }
}

function stopHealthPingLoop() {
  if (healthPingIntervalId != null) {
    window.clearInterval(healthPingIntervalId);
    healthPingIntervalId = null;
  }
}

function startHealthPingLoop() {
  stopHealthPingLoop();
  void runHealthPing();
  healthPingIntervalId = window.setInterval(() => {
    void runHealthPing();
  }, HEALTH_PING_INTERVAL_MS);
}

// ── Connection Status ───────────────────────────────────
function setStatus(online, message) {
  statusIndicator.classList.toggle("online", online);
  statusText.textContent = message;
  connectButton.disabled = online;
  disconnectButton.disabled = !online;
  startAudioButton.disabled = !online;
  stopAudioButton.disabled = true;
  sendButton.disabled = !online || isRequestInFlight;
  chatInput.disabled = isRequestInFlight;
}

// ── Audio Mode ──────────────────────────────────────────
function setMode(nextMode) {
  mode = nextMode;
  const labelMap = {
    idle: "Idle",
    listening: "Listening",
    speaking: "Agent Speaking",
    "awaiting-greeting": "Agent Greeting...",
  };
  audioStatusText.textContent = labelMap[mode] || (mode.charAt(0).toUpperCase() + mode.slice(1));
  if (mode === "speaking") {
    setVoiceSessionLabel("Agent Speaking...");
  } else if (mode === "awaiting-greeting") {
    setVoiceSessionLabel("Agent Greeting...");
  } else if (String(mode).startsWith("listening")) {
    setVoiceSessionLabel("Listening... 話しかけてください");
  } else {
    setVoiceSessionLabel("Idle");
  }

  if (!voiceOrb) return;
  voiceOrb.classList.remove("voice-orb-idle", "voice-orb-listening", "voice-orb-speaking");
  if (mode === "speaking" || mode === "awaiting-greeting") {
    voiceOrb.classList.add("voice-orb-speaking");
  } else if (String(mode).startsWith("listening")) {
    voiceOrb.classList.add("voice-orb-listening");
  } else {
    voiceOrb.classList.add("voice-orb-idle");
  }
}

// ── Audio Level Visualization ───────────────────────────
function updateAudioLevel(rmsValue) {
  const pct = Math.min(100, Math.max(0, rmsValue * 1000));
  audioLevelBar.style.width = pct + "%";
}

function setVoiceSessionLabel(text) {
  if (voiceSessionLabel) {
    voiceSessionLabel.textContent = text;
  }
}

function buildJaggedOrbPath(energy, t) {
  const points = 72;
  const angleStep = (Math.PI * 2) / points;
  const baseRadius = 88;
  const amplitude = 0.4 + Math.min(1, energy) * 4.2;
  const shapePoints = [];
  for (let i = 0; i < points; i++) {
    const angle = i * angleStep;
    const ripple = Math.sin(angle * 5 + t * 0.005) + Math.sin(angle * 7 - t * 0.006);
    const radius = baseRadius + amplitude * ripple;
    const x = radius * Math.cos(angle);
    const y = radius * Math.sin(angle);
    shapePoints.push({ x, y });
  }
  if (shapePoints.length < 2) return "";
  const midpoint = (a, b) => ({ x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 });
  const firstMid = midpoint(shapePoints[0], shapePoints[1]);
  let path = `M ${firstMid.x.toFixed(2)} ${firstMid.y.toFixed(2)} `;
  for (let i = 1; i <= shapePoints.length; i++) {
    const current = shapePoints[i % shapePoints.length];
    const next = shapePoints[(i + 1) % shapePoints.length];
    const mid = midpoint(current, next);
    path += `Q ${current.x.toFixed(2)} ${current.y.toFixed(2)} ${mid.x.toFixed(2)} ${mid.y.toFixed(2)} `;
  }
  return `${path}Z`;
}

function animateVoiceOverlay(timestamp) {
  if (!voiceSessionOverlay?.classList.contains("active")) {
    overlayRafId = null;
    return;
  }
  orbEnergy = Math.max(0, orbEnergy * 0.93);
  if (voiceOrbLargePath) {
    const energy = Math.min(1, orbEnergy);
    voiceOrbLargePath.setAttribute("d", buildJaggedOrbPath(energy, timestamp));
    voiceOrbLargePath.style.strokeWidth = (2 + energy * 1.2).toFixed(2);
  }
  overlayRafId = window.requestAnimationFrame(animateVoiceOverlay);
}

function setOverlayVisible(visible) {
  if (!voiceSessionOverlay) return;
  voiceSessionOverlay.classList.toggle("active", visible);
  if (visible) {
    if (overlayRafId == null) {
      overlayRafId = window.requestAnimationFrame(animateVoiceOverlay);
    }
  } else if (overlayRafId != null) {
    window.cancelAnimationFrame(overlayRafId);
    overlayRafId = null;
  }
}

function pushOrbEnergyFromPcm(channel) {
  if (!channel || channel.length === 0) return;
  let sumSquares = 0;
  for (let i = 0; i < channel.length; i++) {
    sumSquares += channel[i] * channel[i];
  }
  const rms = Math.sqrt(sumSquares / channel.length);
  orbEnergy = Math.max(orbEnergy, Math.min(1, rms * 10));
}

function clearGreetingUnlockTimer() {
  if (greetingUnlockTimerId != null) {
    window.clearTimeout(greetingUnlockTimerId);
    greetingUnlockTimerId = null;
  }
}

function clearPlaybackIdleTimer() {
  if (playbackIdleTimerId != null) {
    window.clearTimeout(playbackIdleTimerId);
    playbackIdleTimerId = null;
  }
}

function schedulePlaybackIdleCheck() {
  clearPlaybackIdleTimer();
  playbackIdleTimerId = window.setTimeout(() => {
    const isPlaybackBusy =
      currentPlaybackSource != null || isPlaybackQueueDraining || playbackQueue.length > 0;
    if (isPlaybackBusy) return;
    if (awaitingAgentGreeting) {
      unlockGreetingAndListening(true);
      return;
    }
    if (mode === "speaking") {
      setMode("listening");
    }
  }, 450);
}

function stopAllPlayback() {
  playbackQueue = [];
  isPlaybackQueueDraining = false;
  clearPlaybackIdleTimer();
  if (currentPlaybackSource) {
    try {
      currentPlaybackSource.stop();
    } catch {}
    currentPlaybackSource = null;
  }
}

function stopGreetingFallbackSpeech() {
  if (!window.speechSynthesis) return;
  if (greetingFallbackUtterance) {
    window.speechSynthesis.cancel();
    greetingFallbackUtterance = null;
  }
}

function playGreetingFallbackSpeech(text) {
  if (!awaitingAgentGreeting) return false;
  if (!window.speechSynthesis || typeof SpeechSynthesisUtterance === "undefined") {
    return false;
  }
  const utteranceText = String(text || "").trim();
  if (!utteranceText) return false;
  if (greetingFallbackUtterance) return true;
  didAttemptGreetingSpeechFallback = true;
  const utterance = new SpeechSynthesisUtterance(utteranceText);
  utterance.lang = "ja-JP";
  utterance.rate = 1.02;
  utterance.onstart = () => {
    hasReceivedGreetingAudio = true;
    setMode("speaking");
    setVoiceSessionLabel("Agent Speaking...");
  };
  utterance.onend = () => {
    greetingFallbackUtterance = null;
    if (awaitingAgentGreeting) {
      unlockGreetingAndListening(true);
    }
  };
  utterance.onerror = () => {
    greetingFallbackUtterance = null;
    if (awaitingAgentGreeting) {
      unlockGreetingAndListening(false, true);
    }
  };
  greetingFallbackUtterance = utterance;
  window.speechSynthesis.speak(utterance);
  return true;
}

function unlockGreetingAndListening(withNotice = true, timeoutFallback = false) {
  if (!awaitingAgentGreeting) return;
  awaitingAgentGreeting = false;
  clearGreetingUnlockTimer();
  clearPlaybackIdleTimer();
  setMode("listening");
  setVoiceSessionLabel("Listening... 話しかけてください");
  if (withNotice) {
    showToast("エージェントの挨拶が完了しました。話しかけてください。", "info", 3000);
    appendMessage("エージェント: 準備できました。どうぞ話しかけてください。", "system");
  } else if (timeoutFallback) {
    appendMessage("挨拶音声はスキップして会話待機に切り替えました。", "system");
  }
}

// ── Chat Messages ───────────────────────────────────────
function appendMessage(text, type) {
  hideThinking();

  const bubble = document.createElement("div");
  bubble.className = `message ${type}`;

  const time = formatTime();
  const roleLabel = type === "user" ? "You" : type === "agent" ? "Agent" : "System";
  const roleIcon = type === "user" ? "user" : type === "agent" ? "bot" : "info";

  bubble.innerHTML = `
    <div class="message-header">
      <i data-lucide="${roleIcon}"></i>
      <span>${roleLabel}</span>
    </div>
    <div class="message-body">${escapeHtml(text)}</div>
    <div class="message-meta">
      <i data-lucide="clock"></i>
      <span>${time}</span>
    </div>
  `;

  messagesArea.appendChild(bubble);
  pruneMessages();
  messagesArea.scrollTop = messagesArea.scrollHeight;
  renderIcons(bubble);
}

function appendLiveText(text) {
  hideThinking();
  if (!liveTextBubble) {
    const bubble = document.createElement("div");
    bubble.className = "message agent";
    bubble.innerHTML = `
      <div class="message-header">
        <i data-lucide="bot"></i>
        <span>Agent</span>
      </div>
      <div class="message-body live-text-body"></div>
      <div class="message-meta">
        <i data-lucide="clock"></i>
        <span>${formatTime()}</span>
      </div>
    `;
    messagesArea.appendChild(bubble);
    pruneMessages();
    renderIcons(bubble);
    liveTextBubble = bubble;
  }
  const body = liveTextBubble.querySelector(".live-text-body");
  if (body) {
    body.textContent += text;
  }
  messagesArea.scrollTop = messagesArea.scrollHeight;
}

function resetLiveTextBubble() {
  liveTextBubble = null;
}

// ── Thinking Bubble ─────────────────────────────────────
function showThinking() {
  if (thinkingBubble) return;
  thinkingBubble = document.createElement("div");
  thinkingBubble.className = "message agent thinking-message";
  thinkingBubble.innerHTML = `
    <div class="message-header">
      <i data-lucide="bot"></i>
      <span>Agent</span>
    </div>
    <div class="thinking-dots">
      <span></span><span></span><span></span>
    </div>
  `;
  messagesArea.appendChild(thinkingBubble);
  messagesArea.scrollTop = messagesArea.scrollHeight;
  renderIcons(thinkingBubble);
}

function hideThinking() {
  if (thinkingBubble) {
    thinkingBubble.remove();
    thinkingBubble = null;
  }
}

// ── Agent Activity Feed ─────────────────────────────────
function handleAgentActivity(payload) {
  const { activity, message, icon, status, detail, request_id: requestId, progress } = payload;

  if (requestId && currentActivityRequestId && requestId !== currentActivityRequestId) {
    clearActivityFeed();
  }
  if (requestId) {
    currentActivityRequestId = requestId;
  }

  if (activity === "thinking") {
    clearActivityFeed();
    updateActivityHeader(currentActivityRequestId, progress, "Thinking");
    addActivityItem("thinking", icon || "brain", message, true, null);
    showThinking();
    return;
  }

  if (activity === "tool_call") {
    markThinkingComplete(true);
    updateActivityHeader(currentActivityRequestId, progress, message || "Tool call");
    addActivityItem("tool-call", icon || "wrench", message, true, null);
    return;
  }

  if (activity === "tool_result") {
    updateActivityHeader(currentActivityRequestId, progress, message || "Tool result");
    markLastToolComplete(status === "success", detail);
    return;
  }

  if (activity === "done") {
    setRequestInFlight(false);
    markThinkingComplete(true);
    updateActivityHeader(currentActivityRequestId, progress, "Completed");
    addActivityItem("done", icon || "check-circle-2", message, false, null);
    return;
  }
}

function clearActivityFeed() {
  activityFeed.innerHTML = "";
  activityCount = 0;
  currentActivityRequestId = null;
  updateActivityHeader(null, null, "Idle");
}

function resetActivityFeed() {
  activityFeed.innerHTML = `
    <div class="activity-empty">
      <i data-lucide="bot" class="empty-icon"></i>
      <p>リクエスト処理時にエージェントの動作がここに表示されます。</p>
    </div>
  `;
  activityCount = 0;
  currentActivityRequestId = null;
  updateActivityHeader(null, null, "Idle");
  renderIcons(activityFeed);
}

async function stopAudioCapture(sendLiveStop = false) {
  if (sendLiveStop && socket && socket.readyState === WebSocket.OPEN) {
    socket.send(JSON.stringify({ type: "live_stop" }));
  }

  stopAllPlayback();

  if (processor) {
    processor.disconnect();
    processor.onaudioprocess = null;
  }
  if (audioCaptureNode) {
    audioCaptureNode.disconnect();
    if (audioCaptureNode.port && audioCaptureNode.port.onmessage) {
      audioCaptureNode.port.onmessage = null;
    }
  }
  if (mediaStream) {
    mediaStream.getTracks().forEach((track) => track.stop());
  }
  if (audioContext) {
    await audioContext.close();
  }
  if (standalonePlaybackContext) {
    await standalonePlaybackContext.close();
  }

  processor = null;
  audioCaptureNode = null;
  awaitingAgentGreeting = false;
  hasReceivedGreetingAudio = false;
  didAttemptGreetingSpeechFallback = false;
  clearGreetingUnlockTimer();
  stopGreetingFallbackSpeech();
  setOverlayVisible(false);
  mediaStream = null;
  audioContext = null;
  standalonePlaybackContext = null;
  audioLevelBar.style.width = "0%";
  startAudioButton.disabled = !socket || socket.readyState !== WebSocket.OPEN;
  stopAudioButton.disabled = true;
  setMode("idle");
}

function addActivityItem(type, iconName, labelText, showSpinner, detailText) {
  activityCount++;

  const emptyEl = activityFeed.querySelector(".activity-empty");
  if (emptyEl) emptyEl.remove();

  const item = document.createElement("div");
  item.className = `activity-item activity-${type}`;
  item.dataset.index = activityCount;

  const iconClass =
    type === "done" ? "done" : type === "tool-call" ? "tool-call" : "thinking";
  const time = formatTime();

  item.innerHTML = `
    <div class="activity-icon ${iconClass}">
      <i data-lucide="${escapeHtml(iconName)}"></i>
    </div>
    <div class="activity-text">
      <div class="activity-label">${escapeHtml(labelText)}</div>
      <div class="activity-time">${time}</div>
      ${detailText ? `<div class="activity-detail">${escapeHtml(detailText)}</div>` : ""}
    </div>
    ${
      showSpinner
        ? '<div class="spinner"></div>'
        : '<div class="activity-check"><i data-lucide="check"></i></div>'
    }
  `;

  activityFeed.appendChild(item);
  activityFeed.scrollTop = activityFeed.scrollHeight;
  renderIcons(item);
}

function markThinkingComplete(success) {
  const items = activityFeed.querySelectorAll(".activity-item.activity-thinking");
  const lastItem = items[items.length - 1];
  if (!lastItem) return;
  const spinner = lastItem.querySelector(".spinner");
  if (!spinner) return;
  spinner.remove();
  const checkDiv = document.createElement("div");
  checkDiv.className = success ? "activity-check" : "activity-check error-check";
  const iconName = success ? "check-circle-2" : "x-circle";
  checkDiv.innerHTML = `<i data-lucide="${iconName}"></i>`;
  lastItem.appendChild(checkDiv);
  renderIcons(checkDiv);
  const iconEl = lastItem.querySelector(".activity-icon");
  if (iconEl) {
    iconEl.classList.remove("thinking");
    iconEl.classList.add(success ? "success" : "error");
  }
}

function markLastToolComplete(success, detailText) {
  const items = activityFeed.querySelectorAll(".activity-item.activity-tool-call");
  const lastItem = items[items.length - 1];
  if (!lastItem) return;

  const spinner = lastItem.querySelector(".spinner");
  if (spinner) {
    spinner.remove();

    const checkDiv = document.createElement("div");
    checkDiv.className = success ? "activity-check" : "activity-check error-check";
    const iconName = success ? "check-circle-2" : "x-circle";
    checkDiv.innerHTML = `<i data-lucide="${iconName}"></i>`;
    lastItem.appendChild(checkDiv);
    renderIcons(checkDiv);
  }

  const iconEl = lastItem.querySelector(".activity-icon");
  if (iconEl) {
    iconEl.classList.remove("tool-call");
    iconEl.classList.add(success ? "success" : "error");
  }

  if (!success && detailText) {
    const textBlock = lastItem.querySelector(".activity-text");
    if (textBlock && !textBlock.querySelector(".activity-detail")) {
      const detailEl = document.createElement("div");
      detailEl.className = "activity-detail";
      detailEl.textContent = detailText;
      textBlock.appendChild(detailEl);
    }
  }
}

function encodePcmToBase64(floatSamples) {
  const int16 = new Int16Array(floatSamples.length);
  for (let i = 0; i < floatSamples.length; i++) {
    int16[i] = Math.max(-1, Math.min(1, floatSamples[i])) * 0x7fff;
  }
  const bytes = new Uint8Array(int16.buffer);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function sendAudioChunk(floatSamples, sampleRate) {
  if (awaitingAgentGreeting) return;
  if (!socket || socket.readyState !== WebSocket.OPEN) return;
  socket.send(
    JSON.stringify({
      type: "audio_chunk",
      audio: encodePcmToBase64(floatSamples),
      sample_rate: sampleRate,
    }),
  );
}

async function setupAudioCaptureNode(source, context) {
  if (typeof AudioWorkletNode === "undefined" || !context.audioWorklet) {
    return false;
  }
  const processorCode = `
class PcmCaptureProcessor extends AudioWorkletProcessor {
  process(inputs) {
    const input = inputs[0];
    if (!input || !input[0]) return true;
    this.port.postMessage(input[0]);
    return true;
  }
}
registerProcessor("pcm-capture-processor", PcmCaptureProcessor);
`;
  const blob = new Blob([processorCode], { type: "application/javascript" });
  const moduleUrl = URL.createObjectURL(blob);
  try {
    await context.audioWorklet.addModule(moduleUrl);
    const workletNode = new AudioWorkletNode(context, "pcm-capture-processor", {
      numberOfInputs: 1,
      numberOfOutputs: 0,
    });
    workletNode.port.onmessage = (event) => {
      const input = event.data;
      if (!(input instanceof Float32Array)) return;
      const rms = Math.sqrt(input.reduce((sum, value) => sum + value * value, 0) / input.length);
      smoothedRms = RMS_SMOOTHING * rms + (1 - RMS_SMOOTHING) * smoothedRms;
      updateAudioLevel(smoothedRms);
      const now = Date.now();
        if (smoothedRms > RMS_SPEECH_THRESHOLD) {
          lastSpeechTimestamp = now;
          if (mode !== "listening") setMode("listening");
          if (currentPlaybackSource) {
            stopAllPlayback();
            if (socket && socket.readyState === WebSocket.OPEN) {
              socket.send(JSON.stringify({ type: "barge_in" }));
            }
          }
        }
      if (
        smoothedRms < RMS_SILENCE_THRESHOLD &&
        lastSpeechTimestamp !== 0 &&
        now - lastSpeechTimestamp > PAUSE_TRIGGER_MS
      ) {
        if (socket && socket.readyState === WebSocket.OPEN) {
          socket.send(JSON.stringify({ type: "speech_pause" }));
        }
        lastSpeechTimestamp = 0;
      }
      sendAudioChunk(input, context.sampleRate);
    };
    source.connect(workletNode);
    audioCaptureNode = workletNode;
    return true;
  } catch {
    return false;
  } finally {
    URL.revokeObjectURL(moduleUrl);
  }
}

// ── Clear Activity Button ───────────────────────────────
clearActivityButton.addEventListener("click", () => {
  resetActivityFeed();
});

voiceSessionCloseButton.addEventListener("click", async () => {
  await stopAudioCapture(true);
});

window.addEventListener("keydown", async (event) => {
  if (event.key !== "Escape") return;
  if (!voiceSessionOverlay?.classList.contains("active")) return;
  await stopAudioCapture(true);
});

// ── WebSocket Connection ────────────────────────────────
gatewayInput.addEventListener("change", () => {
  const value = gatewayInput.value.trim();
  if (value) {
    window.localStorage.setItem(GATEWAY_URL_STORAGE_KEY, value);
  }
});

connectButton.addEventListener("click", () => {
  const url = gatewayInput.value.trim();
  if (!url) {
    showToast("Gateway URL を入力してください。", "warning");
    appendMessage("Gateway URL を入力してください。", "system");
    return;
  }
  manualDisconnectRequested = false;
  window.localStorage.setItem(GATEWAY_URL_STORAGE_KEY, url);
  const myGeneration = ++socketGeneration;
  if (socket && (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING)) {
    socket.close();
  }

  const ws = new WebSocket(url);
  socket = ws;

  ws.addEventListener("open", () => {
    if (socket !== ws || myGeneration !== socketGeneration) return;
    if (hasEverConnected) reconnectCount++;
    hasEverConnected = true;
    hasSocketError = false;
    isLiveSessionActive = false;
    resetLiveTextBubble();
    setStatus(true, "Connected");
    setRequestInFlight(false);
    startHealthPingLoop();
    updateHealthMetrics(null);
    appendMessage("接続しました。", "system");
    showToast("Live Gateway に接続しました。", "success", 2500);
  });

  ws.addEventListener("message", (event) => {
    if (socket !== ws || myGeneration !== socketGeneration) return;
    try {
      const payload = JSON.parse(event.data);

      if (payload.type === "agent_activity") {
        handleAgentActivity(payload);
        return;
      }

      if (payload.type === "agent_response") {
        hideThinking();
        setRequestInFlight(false);
        markThinkingComplete(true);
        updateActivityHeader(payload.request_id || currentActivityRequestId, null, "Response ready");
        if (!isLiveSessionActive) {
          appendMessage(payload.text || "(no response)", "agent");
        }
        return;
      }

      if (payload.type === "live_text") {
        const japaneseText = extractJapaneseText(payload.text || "");
        if (!japaneseText) return;
        appendLiveText(japaneseText);
        return;
      }

      if (payload.type === "live_audio") {
        if (awaitingAgentGreeting) {
          hasReceivedGreetingAudio = true;
        }
        stopGreetingFallbackSpeech();
        setMode("speaking");
        playAudio(payload.audio, payload.mime_type);
        return;
      }

      if (payload.type === "live_status") {
        if (payload.status === "started") {
          isLiveSessionActive = true;
          setOverlayVisible(true);
          resetLiveTextBubble();
          setMode(awaitingAgentGreeting ? "awaiting-greeting" : "listening");
        } else if (
          awaitingAgentGreeting &&
          (payload.status === "greeting_no_audio" || payload.status === "greeting_error")
        ) {
          const fallbackText =
            typeof payload.text === "string" && payload.text.trim()
              ? payload.text.trim()
              : "こんにちは。要件を教えてください。";
          if (!playGreetingFallbackSpeech(fallbackText) && !hasReceivedGreetingAudio) {
            unlockGreetingAndListening(false, true);
          }
        } else if (payload.status === "barge_in") {
          stopAllPlayback();
          setMode("listening (barge-in)");
        } else if (payload.status === "stopped") {
          isLiveSessionActive = false;
          awaitingAgentGreeting = false;
          hasReceivedGreetingAudio = false;
          didAttemptGreetingSpeechFallback = false;
          clearGreetingUnlockTimer();
          clearPlaybackIdleTimer();
          stopGreetingFallbackSpeech();
          setOverlayVisible(false);
          resetLiveTextBubble();
          setMode("idle");
        }
        return;
      }

      if (payload.type === "error") {
        setRequestInFlight(false);
        markThinkingComplete(false);
        showToast(payload.message || "Gateway error", "error");
        updateActivityHeader(currentActivityRequestId, null, "Error");
        appendMessage(payload.message || "Error", "system");
        return;
      }

      if (payload.type === "pong") {
        return;
      }

      appendMessage(event.data, "system");
    } catch {
      appendMessage(event.data, "system");
    }
  });

  ws.addEventListener("close", () => {
    if (myGeneration !== socketGeneration) return;
    void stopAudioCapture(false);
    stopHealthPingLoop();
    const wasError = hasSocketError;
    hasSocketError = false;
    isLiveSessionActive = false;
    awaitingAgentGreeting = false;
    hasReceivedGreetingAudio = false;
    clearGreetingUnlockTimer();
    clearPlaybackIdleTimer();
    setRequestInFlight(false);
    resetLiveTextBubble();
    if (socket === ws) {
      socket = null;
    }
    setStatus(false, "Disconnected");
    updateHealthMetrics(null);
    setMode("idle");
    updateActivityHeader(currentActivityRequestId, null, "Disconnected");
    appendMessage(
      wasError ? "接続エラーで切断しました。" : manualDisconnectRequested ? "手動で切断しました。" : "切断しました。",
      "system",
    );
    if (wasError) {
      showToast("接続エラーが発生しました。Gateway URL と公開設定を確認してください。", "error");
    }
    manualDisconnectRequested = false;
  });

  ws.addEventListener("error", () => {
    if (socket !== ws || myGeneration !== socketGeneration) return;
    hasSocketError = true;
    setRequestInFlight(false);
    markThinkingComplete(false);
    setStatus(false, "Error");
  });
});

disconnectButton.addEventListener("click", () => {
  manualDisconnectRequested = true;
  if (socket) {
    socket.close();
  }
});

// ── Audio Capture ───────────────────────────────────────
startAudioButton.addEventListener("click", async () => {
  if (!socket || socket.readyState !== WebSocket.OPEN) {
    appendMessage("接続してから音声を開始してください。", "system");
    return;
  }

  try {
    mediaStream = await navigator.mediaDevices.getUserMedia({ audio: true });
    audioContext = new AudioContext();
    await audioContext.resume();
    const source = audioContext.createMediaStreamSource(mediaStream);
    awaitingAgentGreeting = true;
    hasReceivedGreetingAudio = false;
    didAttemptGreetingSpeechFallback = false;
    clearPlaybackIdleTimer();
    playbackQueue = [];
    setOverlayVisible(true);
    setVoiceSessionLabel("Agent Greeting...");
    clearGreetingUnlockTimer();
    greetingUnlockTimerId = window.setTimeout(() => {
      if (!hasReceivedGreetingAudio) {
        if (!didAttemptGreetingSpeechFallback) {
          const started = playGreetingFallbackSpeech("こんにちは。要件を教えてください。");
          if (!started) {
            unlockGreetingAndListening(false, true);
          }
          return;
        }
        unlockGreetingAndListening(false, true);
      }
    }, GREETING_UNLOCK_TIMEOUT_MS);
    appendMessage("エージェントが先に話しかけます。応答準備をしてください。", "system");
    setMode("awaiting-greeting");

    const workletReady = await setupAudioCaptureNode(source, audioContext);
    if (!workletReady) {
      processor = audioContext.createScriptProcessor(4096, 1, 1);
      processor.onaudioprocess = (event) => {
        const input = event.inputBuffer.getChannelData(0);
        const rms = Math.sqrt(
          input.reduce((sum, value) => sum + value * value, 0) / input.length,
        );
        smoothedRms = RMS_SMOOTHING * rms + (1 - RMS_SMOOTHING) * smoothedRms;
        updateAudioLevel(smoothedRms);

        const now = Date.now();
        if (smoothedRms > RMS_SPEECH_THRESHOLD) {
          lastSpeechTimestamp = now;
          if (mode !== "listening") {
            setMode("listening");
          }
          if (currentPlaybackSource) {
            stopAllPlayback();
            if (socket && socket.readyState === WebSocket.OPEN) {
              socket.send(JSON.stringify({ type: "barge_in" }));
            }
          }
        }
        if (
          smoothedRms < RMS_SILENCE_THRESHOLD &&
          lastSpeechTimestamp !== 0 &&
          now - lastSpeechTimestamp > PAUSE_TRIGGER_MS
        ) {
          if (socket && socket.readyState === WebSocket.OPEN) {
            socket.send(JSON.stringify({ type: "speech_pause" }));
          }
          lastSpeechTimestamp = 0;
        }
        sendAudioChunk(input, audioContext.sampleRate);
      };
      source.connect(processor);
      processor.connect(audioContext.destination);
      showToast("AudioWorklet 非対応のため互換モードで録音します。", "warning", 2500);
    }

    socket.send(JSON.stringify({ type: "live_start" }));
    startAudioButton.disabled = true;
    stopAudioButton.disabled = false;
  } catch (err) {
    showToast(`音声開始に失敗しました: ${err.message}`, "error");
    appendMessage(`音声開始に失敗しました: ${err.message}`, "system");
  }
});

stopAudioButton.addEventListener("click", async () => {
  await stopAudioCapture(true);
});

// ── Chat Form ───────────────────────────────────────────
function resizeChatInput() {
  chatInput.style.height = "auto";
  const maxHeight = 180;
  const nextHeight = Math.min(chatInput.scrollHeight, maxHeight);
  chatInput.style.height = `${nextHeight}px`;
  chatInput.style.overflowY = chatInput.scrollHeight > maxHeight ? "auto" : "hidden";
}

chatInput.addEventListener("input", resizeChatInput);

chatInput.addEventListener("keydown", (event) => {
  if (event.isComposing || event.keyCode === 229) return;
  if (event.key !== "Enter") return;
  if (event.shiftKey) return; // allow newline on Shift+Enter
  event.preventDefault();
  chatForm.requestSubmit();
});

chatForm.addEventListener("submit", (event) => {
  event.preventDefault();
  if (isRequestInFlight) return;
  if (!socket || socket.readyState !== WebSocket.OPEN) {
    showToast("接続してから送信してください。", "warning");
    appendMessage("接続してから送信してください。", "system");
    return;
  }

  const message = chatInput.value.trim();
  if (!message) return;

  appendMessage(message, "user");
  setRequestInFlight(true);
  socket.send(JSON.stringify({ type: "user_text", text: message }));
  chatInput.value = "";
  resizeChatInput();
  resetLiveTextBubble();
});

// ── Audio Playback ──────────────────────────────────────
function playAudio(base64Audio, mimeType) {
  if (!base64Audio) return;
  playbackQueue.push({ base64Audio, mimeType });
  if (mode !== "speaking") {
    setMode("speaking");
  }
  void drainPlaybackQueue();
}

async function drainPlaybackQueue() {
  if (isPlaybackQueueDraining) return;
  isPlaybackQueueDraining = true;
  try {
    while (playbackQueue.length > 0) {
      const next = playbackQueue.shift();
      if (!next) continue;
      const context = audioContext || standalonePlaybackContext || new AudioContext();
      if (!audioContext && !standalonePlaybackContext) {
        standalonePlaybackContext = context;
      }
      if (context.state === "suspended") {
        await context.resume();
      }
      const audioBytes = Uint8Array.from(atob(next.base64Audio), (c) => c.charCodeAt(0));
      const parsedRate = (() => {
        if (typeof next.mimeType !== "string") return null;
        const m = next.mimeType.match(/rate=(\d+)/i);
        return m ? Number.parseInt(m[1], 10) : null;
      })();
      const sampleRate = parsedRate && Number.isFinite(parsedRate) ? parsedRate : 16000;
      const buffer = context.createBuffer(1, audioBytes.length / 2, sampleRate);
      const channel = buffer.getChannelData(0);
      for (let i = 0; i < channel.length; i++) {
        const low = audioBytes[i * 2];
        const high = audioBytes[i * 2 + 1];
        let sample = (high << 8) | low;
        if (sample >= 0x8000) sample -= 0x10000;
        channel[i] = sample / 0x7fff;
      }
      pushOrbEnergyFromPcm(channel);
      await new Promise((resolve) => {
        const source = context.createBufferSource();
        currentPlaybackSource = source;
        source.buffer = buffer;
        source.connect(context.destination);
        source.onended = () => {
          if (currentPlaybackSource === source) {
            currentPlaybackSource = null;
          }
          resolve();
        };
        source.start();
      });
    }
  } finally {
    isPlaybackQueueDraining = false;
    schedulePlaybackIdleCheck();
  }
}

// ── Initialize ──────────────────────────────────────────
const savedGatewayUrl = window.localStorage.getItem(GATEWAY_URL_STORAGE_KEY);
if (savedGatewayUrl) {
  gatewayInput.value = savedGatewayUrl;
}
setStatus(false, "Disconnected");
setMode("idle");
updateHealthMetrics(null);
updateActivityHeader(null, null, "Idle");
resizeChatInput();
window.addEventListener("beforeunload", () => {
  stopHealthPingLoop();
});
renderIcons();
