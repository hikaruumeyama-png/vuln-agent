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
const activityFeed = document.getElementById("activity-feed");
const clearActivityButton = document.getElementById("clear-activity");

// ── Audio Detection Constants ───────────────────────────
const RMS_SPEECH_THRESHOLD = 0.025;
const RMS_SILENCE_THRESHOLD = 0.012;
const RMS_SMOOTHING = 0.2;
const PAUSE_TRIGGER_MS = 650;

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

// ── Connection Status ───────────────────────────────────
function setStatus(online, message) {
  statusIndicator.classList.toggle("online", online);
  statusText.textContent = message;
  connectButton.disabled = online;
  disconnectButton.disabled = !online;
  startAudioButton.disabled = !online;
  stopAudioButton.disabled = true;
}

// ── Audio Mode ──────────────────────────────────────────
function setMode(nextMode) {
  mode = nextMode;
  audioStatusText.textContent = mode.charAt(0).toUpperCase() + mode.slice(1);
}

// ── Audio Level Visualization ───────────────────────────
function updateAudioLevel(rmsValue) {
  const pct = Math.min(100, Math.max(0, rmsValue * 1000));
  audioLevelBar.style.width = pct + "%";
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
  const { activity, message, icon, status } = payload;

  if (activity === "thinking") {
    clearActivityFeed();
    addActivityItem("thinking", icon || "brain", message, true);
    showThinking();
    return;
  }

  if (activity === "tool_call") {
    addActivityItem("tool-call", icon || "wrench", message, true);
    return;
  }

  if (activity === "tool_result") {
    markLastToolComplete(status === "success");
    return;
  }

  if (activity === "done") {
    addActivityItem("done", icon || "check-circle-2", message, false);
    return;
  }
}

function clearActivityFeed() {
  activityFeed.innerHTML = "";
  activityCount = 0;
}

function resetActivityFeed() {
  activityFeed.innerHTML = `
    <div class="activity-empty">
      <i data-lucide="bot" class="empty-icon"></i>
      <p>リクエスト処理時にエージェントの動作がここに表示されます。</p>
    </div>
  `;
  activityCount = 0;
  renderIcons(activityFeed);
}

async function stopAudioCapture(sendLiveStop = false) {
  if (sendLiveStop && socket && socket.readyState === WebSocket.OPEN) {
    socket.send(JSON.stringify({ type: "live_stop" }));
  }

  if (currentPlaybackSource) {
    try {
      currentPlaybackSource.stop();
    } catch {}
    currentPlaybackSource = null;
  }

  if (processor) {
    processor.disconnect();
    processor.onaudioprocess = null;
  }
  if (mediaStream) {
    mediaStream.getTracks().forEach((track) => track.stop());
  }
  if (audioContext) {
    await audioContext.close();
  }

  processor = null;
  mediaStream = null;
  audioContext = null;
  audioLevelBar.style.width = "0%";
  startAudioButton.disabled = !socket || socket.readyState !== WebSocket.OPEN;
  stopAudioButton.disabled = true;
  setMode("idle");
}

function addActivityItem(type, iconName, labelText, showSpinner) {
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

function markLastToolComplete(success) {
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
}

// ── Clear Activity Button ───────────────────────────────
clearActivityButton.addEventListener("click", () => {
  resetActivityFeed();
});

// ── WebSocket Connection ────────────────────────────────
connectButton.addEventListener("click", () => {
  const url = gatewayInput.value.trim();
  if (!url) {
    appendMessage("Gateway URL を入力してください。", "system");
    return;
  }
  if (socket && (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING)) {
    socket.close();
  }

  socket = new WebSocket(url);

  socket.addEventListener("open", () => {
    hasSocketError = false;
    isLiveSessionActive = false;
    resetLiveTextBubble();
    setStatus(true, "Connected");
    appendMessage("接続しました。", "system");
  });

  socket.addEventListener("message", (event) => {
    try {
      const payload = JSON.parse(event.data);

      if (payload.type === "agent_activity") {
        handleAgentActivity(payload);
        return;
      }

      if (payload.type === "agent_response") {
        hideThinking();
        if (!isLiveSessionActive) {
          appendMessage(payload.text || "(no response)", "agent");
        }
        return;
      }

      if (payload.type === "live_text") {
        appendLiveText(payload.text || "");
        return;
      }

      if (payload.type === "live_audio") {
        setMode("speaking");
        playAudio(payload.audio, payload.mime_type);
        return;
      }

      if (payload.type === "live_status") {
        if (payload.status === "started") {
          isLiveSessionActive = true;
          resetLiveTextBubble();
          setMode("listening");
        } else if (payload.status === "barge_in") {
          setMode("listening (barge-in)");
        } else if (payload.status === "stopped") {
          isLiveSessionActive = false;
          resetLiveTextBubble();
          setMode("idle");
        }
        return;
      }

      if (payload.type === "error") {
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

  socket.addEventListener("close", () => {
    stopAudioCapture(false);
    const wasError = hasSocketError;
    hasSocketError = false;
    isLiveSessionActive = false;
    resetLiveTextBubble();
    socket = null;
    setStatus(false, "Disconnected");
    setMode("idle");
    appendMessage(wasError ? "接続エラーで切断しました。" : "切断しました。", "system");
  });

  socket.addEventListener("error", () => {
    hasSocketError = true;
    setStatus(false, "Error");
  });
});

disconnectButton.addEventListener("click", () => {
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
    const source = audioContext.createMediaStreamSource(mediaStream);
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
          currentPlaybackSource.stop();
          currentPlaybackSource = null;
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

      const int16 = new Int16Array(input.length);
      for (let i = 0; i < input.length; i++) {
        int16[i] = Math.max(-1, Math.min(1, input[i])) * 0x7fff;
      }
      const bytes = new Uint8Array(int16.buffer);
      let binary = '';
      for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
      }
      const base64 = btoa(binary);
      if (socket && socket.readyState === WebSocket.OPEN) {
        socket.send(
          JSON.stringify({
            type: "audio_chunk",
            audio: base64,
            sample_rate: audioContext.sampleRate,
          }),
        );
      }
    };

    source.connect(processor);
    processor.connect(audioContext.destination);
    socket.send(JSON.stringify({ type: "live_start" }));
    setMode("listening");
    startAudioButton.disabled = true;
    stopAudioButton.disabled = false;
  } catch (err) {
    appendMessage(`音声開始に失敗しました: ${err.message}`, "system");
  }
});

stopAudioButton.addEventListener("click", async () => {
  await stopAudioCapture(true);
});

// ── Chat Form ───────────────────────────────────────────
chatInput.addEventListener("keydown", (event) => {
  if (event.key !== "Enter") return;
  if (event.shiftKey) return; // allow newline on Shift+Enter
  event.preventDefault();
  chatForm.requestSubmit();
});

chatForm.addEventListener("submit", (event) => {
  event.preventDefault();
  if (!socket || socket.readyState !== WebSocket.OPEN) {
    appendMessage("接続してから送信してください。", "system");
    return;
  }

  const message = chatInput.value.trim();
  if (!message) return;

  appendMessage(message, "user");
  socket.send(JSON.stringify({ type: "user_text", text: message }));
  chatInput.value = "";
  resetLiveTextBubble();
});

// ── Audio Playback ──────────────────────────────────────
function playAudio(base64Audio, mimeType) {
  if (!base64Audio) return;
  const audioBytes = Uint8Array.from(atob(base64Audio), (c) => c.charCodeAt(0));
  const sampleRate = 16000;
  const context = audioContext || new AudioContext();
  const buffer = context.createBuffer(1, audioBytes.length / 2, sampleRate);
  const channel = buffer.getChannelData(0);
  for (let i = 0; i < channel.length; i++) {
    const low = audioBytes[i * 2];
    const high = audioBytes[i * 2 + 1];
    let sample = (high << 8) | low;
    if (sample >= 0x8000) sample = sample - 0x10000;
    channel[i] = sample / 0x7fff;
  }
  if (currentPlaybackSource) {
    currentPlaybackSource.stop();
  }
  const source = context.createBufferSource();
  source.buffer = buffer;
  source.connect(context.destination);
  source.start();
  currentPlaybackSource = source;
  source.onended = () => {
    if (mode === "speaking") {
      setMode("listening");
    }
  };
}

// ── Initialize ──────────────────────────────────────────
setStatus(false, "Disconnected");
setMode("idle");
renderIcons();
