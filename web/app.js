const statusIndicator = document.getElementById("status-indicator");
const statusText = document.getElementById("status-text");
const connectButton = document.getElementById("connect-button");
const disconnectButton = document.getElementById("disconnect-button");
const gatewayInput = document.getElementById("gateway-url");
const chatForm = document.getElementById("chat-form");
const chatInput = document.getElementById("chat-input");
const messages = document.getElementById("messages");
const startAudioButton = document.getElementById("start-audio");
const stopAudioButton = document.getElementById("stop-audio");
const audioStatus = document.getElementById("audio-status");

const RMS_SPEECH_THRESHOLD = 0.025;
const RMS_SILENCE_THRESHOLD = 0.012;
const RMS_SMOOTHING = 0.2;
const PAUSE_TRIGGER_MS = 650;

let socket = null;
let audioContext = null;
let mediaStream = null;
let processor = null;
let currentPlaybackSource = null;
let lastSpeechTimestamp = 0;
let smoothedRms = 0;
let mode = "idle";

function setStatus(online, message) {
  statusIndicator.classList.toggle("online", online);
  statusIndicator.classList.toggle("offline", !online);
  statusText.textContent = message;
  connectButton.disabled = online;
  disconnectButton.disabled = !online;
  startAudioButton.disabled = !online;
  stopAudioButton.disabled = true;
}

function setMode(nextMode) {
  mode = nextMode;
  audioStatus.textContent = `Audio: ${mode}`;
}

function appendMessage(text, type) {
  const bubble = document.createElement("div");
  bubble.className = `message ${type}`;
  bubble.textContent = text;
  messages.appendChild(bubble);
  messages.scrollTop = messages.scrollHeight;
}

connectButton.addEventListener("click", () => {
  const url = gatewayInput.value.trim();
  if (!url) {
    appendMessage("Gateway URL を入力してください。", "system");
    return;
  }

  socket = new WebSocket(url);

  socket.addEventListener("open", () => {
    setStatus(true, "Connected");
    appendMessage("接続しました。", "system");
  });

  socket.addEventListener("message", (event) => {
    try {
      const payload = JSON.parse(event.data);
      if (payload.type === "agent_response") {
        appendMessage(payload.text || "(no response)", "agent");
        return;
      }
      if (payload.type === "live_text") {
        appendMessage(payload.text || "(no response)", "agent");
        return;
      }
      if (payload.type === "live_audio") {
        setMode("speaking");
        playAudio(payload.audio, payload.mime_type);
        return;
      }
      if (payload.type === "live_status") {
        if (payload.status === "started") {
          setMode("listening");
        } else if (payload.status === "barge_in") {
          setMode("listening (barge-in)");
        } else if (payload.status === "stopped") {
          setMode("idle");
        }
        return;
      }
      if (payload.type === "error") {
        appendMessage(payload.message || "Error", "system");
        return;
      }
      appendMessage(event.data, "system");
    } catch (error) {
      appendMessage(event.data, "system");
    }
  });

  socket.addEventListener("close", () => {
    setStatus(false, "Disconnected");
    setMode("idle");
    appendMessage("切断しました。", "system");
  });

  socket.addEventListener("error", () => {
    setStatus(false, "Error");
    setMode("idle");
    appendMessage("接続に失敗しました。", "system");
  });
});

disconnectButton.addEventListener("click", () => {
  if (socket) {
    socket.close();
  }
});

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
        input.reduce((sum, value) => sum + value * value, 0) / input.length
      );
      smoothedRms = RMS_SMOOTHING * rms + (1 - RMS_SMOOTHING) * smoothedRms;
      const now = Date.now();
      if (smoothedRms > RMS_SPEECH_THRESHOLD) {
        lastSpeechTimestamp = now;
        if (mode !== "listening") {
          setMode("listening");
        }
        if (currentPlaybackSource) {
          currentPlaybackSource.stop();
          currentPlaybackSource = null;
          socket.send(JSON.stringify({ type: "barge_in" }));
        }
      }
      if (
        smoothedRms < RMS_SILENCE_THRESHOLD &&
        lastSpeechTimestamp !== 0 &&
        now - lastSpeechTimestamp > PAUSE_TRIGGER_MS
      ) {
        socket.send(JSON.stringify({ type: "speech_pause" }));
        lastSpeechTimestamp = 0;
      }
      const int16 = new Int16Array(input.length);
      for (let i = 0; i < input.length; i++) {
        int16[i] = Math.max(-1, Math.min(1, input[i])) * 0x7fff;
      }
      const bytes = new Uint8Array(int16.buffer);
      const base64 = btoa(String.fromCharCode(...bytes));
      socket.send(
        JSON.stringify({
          type: "audio_chunk",
          audio: base64,
          sample_rate: audioContext.sampleRate,
        })
      );
    };

    source.connect(processor);
    processor.connect(audioContext.destination);
    socket.send(JSON.stringify({ type: "live_start" }));
    setMode("listening");
    startAudioButton.disabled = true;
    stopAudioButton.disabled = false;
  } catch (error) {
    appendMessage(`音声開始に失敗しました: ${error.message}`, "system");
  }
});

stopAudioButton.addEventListener("click", async () => {
  if (processor) processor.disconnect();
  if (mediaStream) mediaStream.getTracks().forEach((track) => track.stop());
  if (audioContext) audioContext.close();

  processor = null;
  mediaStream = null;
  audioContext = null;

  if (socket && socket.readyState === WebSocket.OPEN) {
    socket.send(JSON.stringify({ type: "live_stop" }));
  }
  setMode("idle");
  startAudioButton.disabled = false;
  stopAudioButton.disabled = true;
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
});

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

setStatus(false, "Disconnected");
setMode("idle");
