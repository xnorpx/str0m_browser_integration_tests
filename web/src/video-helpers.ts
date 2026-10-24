import {ServerMessage} from './protocol';

export const DD_URI = 'https://aomediacodec.github.io/av1-rtp-spec/#dependency-descriptor-rtp-header-extension';
export const delay = (ms: number) => new Promise<void>(resolve => setTimeout(resolve, ms));

export function expectMessage<T extends ServerMessage['type']>(
  message: ServerMessage, type: T,
): Extract<ServerMessage, {type: T}> {
  if (message.type !== type) throw new Error(`Expected ${type}: ${JSON.stringify(message)}`);
  return message as Extract<ServerMessage, {type: T}>;
}

export async function until<T>(label: string, sample: () => Promise<T>, done: (value: T) => boolean): Promise<T> {
  const deadline = performance.now() + 15000;
  let value: T;
  do {
    value = await sample();
    if (done(value)) return value;
    await delay(100);
  } while (performance.now() < deadline);
  throw new Error(`Timed out: ${label}; last sample=${JSON.stringify(value)}`);
}

export function syntheticVideo(width = 640, height = 360, textured = false): {
  stream: MediaStream; pause: () => void; stop: () => void;
} {
  const canvas = document.createElement('canvas');
  canvas.width = width;
  canvas.height = height;
  const context = canvas.getContext('2d');
  if (!context) throw new Error('Canvas 2D unavailable');
  const background = context.createImageData(width, height);
  let noise = 12345;
  for (let i = 0; i < background.data.length; i += 4) {
    noise = (Math.imul(noise, 1664525) + 1013904223) >>> 0;
    background.data[i] = background.data[i + 1] = background.data[i + 2] = 32 + (noise >>> 25);
    background.data[i + 3] = 255;
  }
  let frame = 0;
  const draw = () => {
    if (textured) context.putImageData(background, 0, 0);
    else {
      context.fillStyle = '#14304c';
      context.fillRect(0, 0, width, height);
    }
    context.fillStyle = '#e9ba34';
    context.fillRect((frame * 7) % (width - 80), 40, 80, 80);
    context.fillStyle = '#ffffff';
    context.font = `${width >= 640 ? 32 : 18}px monospace`;
    context.fillText(`str0m DD frame ${frame++}`, 20, height - 30);
  };
  draw();
  const stream = canvas.captureStream(30);
  const timer = setInterval(draw, 1000 / 30);
  return {
    stream,
    pause: () => clearInterval(timer),
    stop: () => { clearInterval(timer); stream.getTracks().forEach(track => track.stop()); },
  };
}

/** Telemetry is distinct from the data-channel echo success signal. */
export function channelStats<T>(dc: RTCDataChannel, command: string): Promise<T> {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      dc.removeEventListener('message', onMessage);
      reject(new Error(`Timed out waiting for ${command}`));
    }, 3000);
    function onMessage(event: MessageEvent) {
      if (event.data === 'ready') return;
      clearTimeout(timeout);
      dc.removeEventListener('message', onMessage);
      try { resolve(JSON.parse(event.data) as T); }
      catch (error) { reject(error); }
    }
    dc.addEventListener('message', onMessage);
    dc.send(command);
  });
}

export async function decoded(pc: RTCPeerConnection): Promise<{frames: number; keys: number; codec: string}> {
  const stats = await pc.getStats();
  let result = {frames: 0, keys: 0, codec: ''};
  stats.forEach(stat => {
    if (stat.type === 'inbound-rtp' && stat.kind === 'video') {
      result = {
        frames: stat.framesDecoded ?? 0,
        keys: stat.keyFramesDecoded ?? 0,
        codec: stats.get(stat.codecId)?.mimeType ?? '',
      };
    }
  });
  return result;
}
