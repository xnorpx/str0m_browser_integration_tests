/**
 * Karma framework plugin that builds and manages the Pion Go test server.
 *
 * Lifecycle:
 *   1. `go build` the pion server binary (skipped if PREBUILT_PION_SERVER is set).
 *   2. Find an available TCP port for the WebSocket signaling server.
 *   3. Spawn the pion server with: -ws-port <port> -adv-addr <lan-ip> -pcap-dir <dir>
 *   4. Wait for the "SERVER READY" line on stdout.
 *   5. Inject `config.client.serverWsPort` so browser tests can connect.
 *   6. Kill the server when Karma exits.
 *
 * Environment variables:
 *   PREBUILT_PION_SERVER  - Path to a pre-built pion server binary (skips go build).
 *   PION_PCAP_DIR         - Directory for pcap captures (default: target/pcap).
 */
'use strict';

const { spawn, execSync } = require('child_process');
const path = require('path');
const net = require('net');
const readline = require('readline');
const os = require('os');

const PREBUILT = process.env.PREBUILT_PION_SERVER;
const PCAP_DIR = process.env.PION_PCAP_DIR || 'target/pcap';

// Same readiness format as the str0m server.
const READY_RE = /^SERVER READY ws:\/\/([\d.]+):(\d+)$/;

/**
 * Resolve the path to the pion server binary, building it if necessary.
 */
function resolvePionBinary(projectRoot) {
    if (PREBUILT) {
        console.log(`[pion-server] Using pre-built binary: ${PREBUILT}`);
        return PREBUILT;
    }

    const pionDir = path.join(projectRoot, 'pion');
    const ext = os.platform() === 'win32' ? '.exe' : '';
    const bin = path.join(pionDir, `server${ext}`);

    console.log(`[pion-server] Building pion server with go build...`);
    try {
        execSync(`go build -o server${ext} ./cmd/server/`, {
            cwd: pionDir,
            stdio: ['ignore', 'inherit', 'inherit'],
        });
    } catch (e) {
        throw new Error(`[pion-server] go build failed: ${e.message}`);
    }

    console.log(`[pion-server] Server binary: ${bin}`);
    return bin;
}

/**
 * Find an available TCP port.
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
 * Spawn the pion server and wait for the ready indicator on stdout.
 */
function startServer(binary, wsPort, projectRoot) {
    return new Promise((resolve, reject) => {
        const advAddr = getLanIp();
        const pcapDir = path.resolve(projectRoot, PCAP_DIR);
        const args = [
            `-ws-port=${wsPort}`,
            `-adv-addr=${advAddr}`,
            `-pcap-dir=${pcapDir}`,
        ];

        console.log(`[pion-server] Spawning: ${binary} ${args.join(' ')}`);

        const proc = spawn(binary, args, {
            cwd: projectRoot,
            stdio: ['ignore', 'pipe', 'pipe'],
        });

        let settled = false;

        const rlOut = readline.createInterface({ input: proc.stdout });
        const rlErr = readline.createInterface({ input: proc.stderr });

        rlOut.on('line', (line) => {
            console.log(`[pion-server/stdout] ${line}`);
            const m = READY_RE.exec(line);
            if (!settled && m) {
                settled = true;
                const ip = m[1];
                const port = parseInt(m[2], 10);
                console.log(`[pion-server] Detected ready: ip=${ip} port=${port}`);
                resolve({ proc, ip, port });
            }
        });

        rlErr.on('line', (line) => {
            console.log(`[pion-server/stderr] ${line}`);
        });

        proc.on('error', (err) => {
            if (!settled) {
                settled = true;
                reject(new Error(`[pion-server] Failed to start: ${err.message}`));
            }
        });

        proc.on('exit', (code, signal) => {
            console.log(`[pion-server] Server exited: code=${code} signal=${signal}`);
            if (!settled) {
                settled = true;
                reject(new Error(`[pion-server] Server exited before ready (code=${code})`));
            }
        });

        setTimeout(() => {
            if (!settled) {
                settled = true;
                proc.kill();
                reject(new Error('[pion-server] Timed out waiting for server to be ready'));
            }
        }, 30000);
    });
}

function createPionServerPlugin() {
    let serverProc = null;
    let wsPort = null;
    let serverIp = null;

    return {
        async setup(config) {
            const projectRoot = path.resolve(__dirname, '..', '..');
            const binary = resolvePionBinary(projectRoot);

            const allocatedPort = await findAvailablePort();
            console.log(`[pion-server] Allocated WS port: ${allocatedPort}`);

            const result = await startServer(binary, allocatedPort, projectRoot);
            serverProc = result.proc;
            serverIp = result.ip;
            wsPort = result.port;

            console.log(`[pion-server] Server is ready on ws://${serverIp}:${wsPort}`);

            config.client = config.client || {};
            config.client.serverWsPort = wsPort;
            config.client.serverIp = serverIp;
        },

        teardown() {
            if (serverProc) {
                console.log('[pion-server] Stopping server...');
                serverProc.kill();
                serverProc = null;
            }
        },

        get port() {
            return wsPort;
        },
    };
}

const serverPlugin = createPionServerPlugin();

function pionServerFrameworkFactory(config, emitter) {
    const setupPromise = serverPlugin.setup(config);

    emitter.on('exit', (done) => {
        serverPlugin.teardown();
        done();
    });

    return setupPromise;
}

pionServerFrameworkFactory.$inject = ['config', 'emitter'];

module.exports = {
    'framework:pion-server': ['factory', pionServerFrameworkFactory],
};
