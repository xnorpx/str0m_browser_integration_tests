/**
 * Karma framework plugin that builds and manages the str0m Rust test server.
 *
 * Lifecycle:
 *   1. (Optional) `cargo build --bin server` - skipped if PREBUILT_SERVER_BINARY is set.
 *   2. Find an available TCP port for the WebSocket signaling server.
 *   3. Spawn the server binary with: --ws-port <port> --udp-port-start 0 --adv-addr <lan-ip>
 *   4. Wait for the "Listening on" log line on stdout/stderr.
 *   5. Inject `config.client.serverWsPort` so browser tests can connect.
 *   6. Kill the server when Karma exits.
 *
 * Environment variables:
 *   PREBUILT_SERVER_BINARY  - Path to a pre-built server binary (skips cargo build).
 *   CARGO                   - Path to the cargo binary (default: "cargo").
 *   RUST_LOG                - Passed through to the server (default: "info,str0m=warn,sctp_proto=warn").
 */
'use strict';

const {spawn, execSync} = require('child_process');
const path = require('path');
const net = require('net');
const readline = require('readline');
const os = require('os');

const CARGO_BIN = process.env.CARGO || 'cargo';
const PREBUILT = process.env.PREBUILT_SERVER_BINARY;
const RUST_LOG = process.env.RUST_LOG || 'info,str0m=warn,sctp_proto=warn';

// Regex matching the server's machine-readable readiness line on stdout.
// Format: SERVER READY ws://<ip>:<port>
const READY_RE = /^SERVER READY ws:\/\/([\d.]+):(\d+)$/;

/**
 * Resolve the path to the server binary, building it if necessary.
 */
function resolveServerBinary(projectRoot) {
  if (PREBUILT) {
    console.log(`[str0m-server] Using pre-built binary: ${PREBUILT}`);
    return PREBUILT;
  }

  const ext = os.platform() === 'win32' ? '.exe' : '';
  const bin = path.join(projectRoot, 'target', 'debug', `server${ext}`);

  console.log(`[str0m-server] Building server binary with cargo...`);
  try {
    execSync(`${CARGO_BIN} build --bin server`, {
      cwd: projectRoot,
      stdio: ['ignore', 'inherit', 'inherit'],
    });
  } catch (e) {
    throw new Error(`[str0m-server] cargo build failed: ${e.message}`);
  }

  console.log(`[str0m-server] Server binary: ${bin}`);
  return bin;
}

/**
 * Find an available TCP port by binding to port 0 and reading back the assigned port.
 */
function findAvailablePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.listen(0, '127.0.0.1', () => {
      const port = srv.address().port;
      srv.close(() => resolve(port));
    });
    srv.on('error', reject);
  });
}

/**
 * Get the machine's first non-internal IPv4 address (LAN IP).
 * Falls back to '127.0.0.1' if none found.
 */
function getLanIp() {
  const interfaces = os.networkInterfaces();
  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]) {
      if (iface.family === 'IPv4' && !iface.internal) {
        return iface.address;
      }
    }
  }
  return '127.0.0.1';
}

/**
 * Spawn the server and wait for the ready indicator on stdout.
 * Returns { proc, ip, port } parsed from: SERVER READY ws://<ip>:<port>
 */
function startServer(binary, wsPort, projectRoot) {
  return new Promise((resolve, reject) => {
    // Use LAN IP so Firefox (which ignores loopback prefs) can reach the server.
    // Chrome/Edge also work fine with the LAN IP.
    const advAddr = getLanIp();
    const args = [
      '--ws-port', String(wsPort),
      '--udp-port-start', '0',
      '--adv-addr', advAddr,
    ];

    console.log(`[str0m-server] Spawning: ${binary} ${args.join(' ')}`);

    const proc = spawn(binary, args, {
      cwd: projectRoot,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: {...process.env, RUST_LOG},
    });

    let settled = false;

    // stdout carries the machine-readable readiness line (println!).
    const rlOut = readline.createInterface({input: proc.stdout});
    // stderr carries tracing logs - forward them for debugging.
    const rlErr = readline.createInterface({input: proc.stderr});

    rlOut.on('line', (line) => {
      console.log(`[str0m-server/stdout] ${line}`);
      const m = READY_RE.exec(line);
      if (!settled && m) {
        settled = true;
        const ip = m[1];
        const port = parseInt(m[2], 10);
        console.log(`[str0m-server] Detected ready: ip=${ip} port=${port}`);
        resolve({proc, ip, port});
      }
    });

    rlErr.on('line', (line) => {
      console.log(`[str0m-server/stderr] ${line}`);
    });

    proc.on('error', (err) => {
      if (!settled) {
        settled = true;
        reject(new Error(`[str0m-server] Failed to start: ${err.message}`));
      }
    });

    proc.on('exit', (code, signal) => {
      console.log(`[str0m-server] Server exited: code=${code} signal=${signal}`);
      if (!settled) {
        settled = true;
        reject(new Error(`[str0m-server] Server exited before ready (code=${code})`));
      }
    });

    // Safety timeout (30 seconds for cargo build + server startup).
    setTimeout(() => {
      if (!settled) {
        settled = true;
        proc.kill();
        reject(new Error('[str0m-server] Timed out waiting for server to be ready'));
      }
    }, 30000);
  });
}

/**
 * Create the Karma plugin object.
 */
function createStr0mServerPlugin() {
  let serverProc = null;
  let wsPort = null;
  let serverIp = null;

  const plugin = {
    /**
     * Called during Karma config phase. Modifies config to inject server info.
     * Returns a promise that resolves when the server is ready.
     */
    async setup(config) {
      const projectRoot = path.resolve(__dirname, '..', '..');
      const binary = resolveServerBinary(projectRoot);

      const allocatedPort = await findAvailablePort();
      console.log(`[str0m-server] Allocated WS port: ${allocatedPort}`);

      const result = await startServer(binary, allocatedPort, projectRoot);
      serverProc = result.proc;
      serverIp = result.ip;
      wsPort = result.port;

      console.log(`[str0m-server] Server is ready on ws://${serverIp}:${wsPort}`);

      // Inject port into Karma client config so tests can access it.
      config.client = config.client || {};
      config.client.serverWsPort = wsPort;
      config.client.serverIp = serverIp;
    },

    /**
     * Kill the server process.
     */
    teardown() {
      if (serverProc) {
        console.log('[str0m-server] Stopping server...');
        serverProc.kill();
        serverProc = null;
      }
    },

    get port() {
      return wsPort;
    },
  };

  return plugin;
}

// Singleton instance shared between the framework and the shutdown hook.
const serverPlugin = createStr0mServerPlugin();

/**
 * Karma framework factory (async).
 * Karma supports returning a promise from framework['$inject'] functions
 * by using the 'ready' callback pattern.
 */
function str0mServerFrameworkFactory(config, emitter) {
  // Start the server during Karma initialization.
  const setupPromise = serverPlugin.setup(config);

  // Karma framework factories are synchronous, but we need async.
  // We block Karma startup by hooking into the 'browsers_ready' phase
  // through the emitter. Instead, we use a middleware that delays the
  // first request until the server is ready.

  // Register cleanup on Karma exit.
  emitter.on('exit', (done) => {
    serverPlugin.teardown();
    done();
  });

  return setupPromise;
}

str0mServerFrameworkFactory.$inject = ['config', 'emitter'];

module.exports = {
  // Export as a Karma framework plugin.
  // Usage in karma.conf.js:
  //   plugins: [require('./plugins/karma-str0m-server')]
  //   frameworks: ['str0m-server', 'jasmine']
  'framework:str0m-server': ['factory', str0mServerFrameworkFactory],
};
