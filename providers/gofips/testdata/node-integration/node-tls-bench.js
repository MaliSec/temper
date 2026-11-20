// node-tls-bench.js - TLS benchmark in the Temper node image
// (OpenSSL 4.0.3). run-tls-bench.sh runs it once under the gofips-only
// config and once under a default-provider control, each in its own
// container. Server and client share this process.
//
// Measures (native execution only; QEMU numbers are not performance data):
//   1. serial handshake latency (median/p95) and handshakes/sec
//   2. concurrent handshake latency and success rate
//   3. bulk echo throughput
//   4. process CPU time and peak RSS
// The last output line is JSON.
const tls = require('node:tls');
const fs = require('node:fs');
const { execFileSync } = require('node:child_process');

const WARMUP = 20;          // handshakes discarded before sampling
const N_SERIAL = 100;       // serial handshake samples
const N_CONCURRENT = 100;   // total handshakes in the concurrent phase
const CONCURRENCY = 20;     // in flight at once (realistic server load)
const BULK_BYTES = 16 * 1024 * 1024; // 16 MiB each direction
const CHUNK = 16 * 1024;    // write chunk
const ROUNDS = parseInt(process.env.BENCH_ROUNDS || '3', 10); // repeats for stability

const KEY = fs.readFileSync('/gofips/tls-key.pem');
const CERT = fs.readFileSync('/gofips/tls-cert.pem');

function percentile(sorted, p) {
  const i = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length));
  return sorted[i];
}

function makeServer() {
  const server = tls.createServer({
    key: KEY, cert: CERT, minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3',
    secureOptions: 0x4000, // SSL_OP_NO_TICKET: every handshake is a full one
  }, (s) => { s.on('data', (d) => s.write(d)); });
  return server;
}

function handshakeOnce(port) {
  return new Promise((resolve, reject) => {
    const t0 = process.hrtime.bigint();
    const s = tls.connect({ host: '127.0.0.1', port, rejectUnauthorized: false,
      minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3' }, () => {
      const dt = Number(process.hrtime.bigint() - t0) / 1e6;
      resolve({ socket: s, ms: dt });
    });
    s.on('error', reject);
  });
}

function serialPhase(port) {
  return new Promise(async (resolve) => {
    for (let i = 0; i < WARMUP; i++) {
      const h = await handshakeOnce(port);
      h.socket.end();
    }
    const samples = [];
    for (let i = 0; i < N_SERIAL; i++) {
      const h = await handshakeOnce(port);
      samples.push(h.ms);
      h.socket.end();
    }
    const sorted = [...samples].sort((a, b) => a - b);
    resolve({
      n: N_SERIAL,
      median: percentile(sorted, 50),
      p95: percentile(sorted, 95),
      min: sorted[0],
      max: sorted[sorted.length - 1],
      handshakes_per_sec: 1000 / percentile(sorted, 50),
    });
  });
}

function concurrentPhase(port) {
  return new Promise(async (resolve) => {
    // warmup
    for (let i = 0; i < WARMUP; i++) { const h = await handshakeOnce(port); h.socket.end(); }
    const latencies = [];
    let success = 0, failed = 0;
    const t0 = process.hrtime.bigint();
    let inFlight = 0, launched = 0;
    await new Promise((done) => {
      function launch() {
        while (inFlight < CONCURRENCY && launched < N_CONCURRENT) {
          inFlight++; launched++;
          handshakeOnce(port).then(({ socket, ms }) => {
            latencies.push(ms); success++;
            socket.end(); inFlight--;
            if (launched === N_CONCURRENT && inFlight === 0) done();
            else launch();
          }).catch(() => {
            failed++; inFlight--;
            if (launched === N_CONCURRENT && inFlight === 0) done();
            else launch();
          });
        }
      }
      launch();
    });
    const wall = Number(process.hrtime.bigint() - t0) / 1e6;
    const sorted = [...latencies].sort((a, b) => a - b);
    resolve({
      n: N_CONCURRENT, concurrency: CONCURRENCY,
      success, failed,
      median: percentile(sorted, 50),
      p95: percentile(sorted, 95),
      wall_ms: wall,
      handshakes_per_sec: (success * 1000) / wall,
    });
  });
}

function bulkPhase(port) {
  return new Promise(async (resolve) => {
    const { socket } = await handshakeOnce(port);
    const payload = Buffer.alloc(CHUNK, 0x61);
    let received = 0;
    const t0 = process.hrtime.bigint();
    const bytes = BULK_BYTES;
    // client -> server -> client echo; count received bytes
    socket.on('data', (d) => {
      received += d.length;
      if (received >= bytes) {
        const dt = Number(process.hrtime.bigint() - t0) / 1e3; // µs
        const mib = (bytes / (1024 * 1024));
        const mibs = mib / (dt / 1e6);
        socket.end();
        resolve({ bytes, roundtrip_us: dt, mib_per_sec: mibs });
      }
    });
    // pipeline the writes (TCP/TLS backpressure applies)
    for (let i = 0; i < bytes / CHUNK; i++) {
      if (!socket.write(payload)) {
        await new Promise((r) => socket.once('drain', r));
      }
    }
    setTimeout(() => resolve({ bytes, error: 'timeout' }), 30000);
  });
}

function cpuAndMem() {
  // /proc/self/status VmHWM (peak RSS kB) + process CPU via /proc/self/stat
  try {
    const st = fs.readFileSync('/proc/self/stat', 'utf8').split(' ');
    const utime = parseInt(st[13], 10) * 10; // ticks -> ms (100Hz)
    const stime = parseInt(st[14], 10) * 10;
    const status = fs.readFileSync('/proc/self/status', 'utf8');
    const hwm = /VmHWM:\s+(\d+)/.exec(status);
    return { cpu_ms: utime + stime, peak_rss_kb: hwm ? parseInt(hwm[1], 10) : null };
  } catch { return { cpu_ms: null, peak_rss_kb: null }; }
}

async function main() {
  const results = { rounds: [] };
  for (let r = 0; r < ROUNDS; r++) {
    const server = makeServer();
    await new Promise((res) => server.listen(0, '127.0.0.1', res));
    const port = server.address().port;
    const serial = await serialPhase(port);
    const concurrent = await concurrentPhase(port);
    const bulk = await bulkPhase(port);
    const c = cpuAndMem();
    server.closeAll && server.closeAll();
    await new Promise((res) => server.close(res));
    results.rounds.push({ round: r + 1, serial, concurrent, bulk, cpu: c });
    console.log(`round ${r + 1}: serial median=${serial.median.toFixed(2)}ms p95=${serial.p95.toFixed(2)}ms hs/s=${serial.handshakes_per_sec.toFixed(1)} | conc ${concurrent.success}/${concurrent.n} med=${concurrent.median.toFixed(2)}ms hs/s=${concurrent.handshakes_per_sec.toFixed(1)} | bulk ${bulk.mib_per_sec ? bulk.mib_per_sec.toFixed(1) + ' MiB/s' : bulk.error}`);
  }
  // aggregate medians across rounds
  function agg(key, sel) {
    const vals = results.rounds.map((r) => sel(r)).filter((v) => typeof v === 'number').sort((a, b) => a - b);
    return vals.length ? percentile(vals, 50) : null;
  }
  const summary = {
    serial_median_ms: agg(0, (r) => r.serial.median),
    serial_p95_ms: agg(0, (r) => r.serial.p95),
    serial_hs_per_sec: agg(0, (r) => r.serial.handshakes_per_sec),
    concurrent_success_rate: results.rounds[0].concurrent.success / results.rounds[0].concurrent.n,
    concurrent_median_ms: agg(0, (r) => r.concurrent.median),
    concurrent_p95_ms: agg(0, (r) => r.concurrent.p95),
    concurrent_hs_per_sec: agg(0, (r) => r.concurrent.handshakes_per_sec),
    bulk_mib_per_sec: agg(0, (r) => r.bulk.mib_per_sec),
    cpu_ms_total: results.rounds[results.rounds.length - 1].cpu.cpu_ms,
    peak_rss_kb: results.rounds[results.rounds.length - 1].cpu.peak_rss_kb,
  };
  results.summary = summary;
  console.log('BENCH-JSON ' + JSON.stringify(summary));
}

main().catch((e) => { console.log('BENCH-FATAL', e.message); process.exit(1); });
