import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';

test('live fixture attaches its own layer with zero, one, or multiple package defaults', () => {
  for (const count of [0, 1, 2]) {
    const dir = mkdtempSync(join(tmpdir(), 'cma-layers-'));
    try {
      const layer = 'TEST_FIXTURE_Test_Access';
      writeFileSync(join(dir, 'session.json'), '{"sid":"mock"}');
      writeFileSync(join(dir, 'defaults.json'), JSON.stringify({ 'access-layers': Array.from({ length: count }, (_, i) => ({ uid: `uid-${i}`, name: `default-${i}` })) }));
      writeFileSync(join(dir, 'attached.json'), JSON.stringify({ 'access-layers': [{ uid: 'test-layer', name: layer }] }));
      writeFileSync(join(dir, 'rules.json'), JSON.stringify({ rulebase: Array.from({ length: 100 }, (_, i) => ({ uid: `rule-${i}`, type: 'access-rule' })) }));
      writeFileSync(join(dir, 'mgmt_cli'), `#!/bin/sh
printf '%s\\0' "$@" >> "$FIXTURE_DIR/calls"
printf '\\0' >> "$FIXTURE_DIR/calls"
case "$1 $2" in
  'show package')
    if [ -f "$FIXTURE_DIR/seen" ]; then
      cat "$FIXTURE_DIR/attached.json"
    else
      touch "$FIXTURE_DIR/seen"
      cat "$FIXTURE_DIR/defaults.json"
    fi ;;
  'show access-rulebase') cat "$FIXTURE_DIR/rules.json" ;;
  *) printf '{"uid":"mock"}\\n' ;;
esac
`, { mode: 0o700 });
      execFileSync('bash', [new URL('../scripts/build-test-policy.sh', import.meta.url).pathname,
        '--prefix', 'TEST_FIXTURE', '--seed', '42', '--execute', '--session', join(dir, 'session.json')],
      { env: { ...process.env, PATH: `${dir}:${process.env.PATH}`, FIXTURE_DIR: dir }, stdio: ['pipe', 'pipe', 'pipe'] });
      const calls = readFileSync(join(dir, 'calls'), 'utf8').split('\0\0').filter(Boolean).map(c => c.split('\0'));
      const set = calls.find(c => c[0] === 'set' && c[1] === 'package');
      const fields = Object.fromEntries(Array.from({ length: (set.length - 2) / 2 }, (_, i) => set.slice(2 + i * 2, 4 + i * 2)));
      assert.equal(fields['access-layers.add.1.name'], layer);
      assert.equal(fields['access-layers.add.1.position'], '1');
      assert.ok(!set.includes('access-layers.remove.1'), 'Layer add and remove must use separate API calls');
      const removal = calls.find(c => c[0] === 'set' && c.includes('access-layers.remove.1'));
      assert.equal(Boolean(removal), count > 0);
      for (let i = 0; i < count; i++) assert.equal(removal[removal.indexOf(`access-layers.remove.${i+1}`) + 1], `default-${i}`);
      assert.equal(calls.filter(c => c[0] === 'add' && c[1] === 'access-rule').length, 100);
      assert.ok(!calls.some(c => ['delete', 'publish', 'install-policy'].includes(c[0])));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }
});

test('policy fixture keeps exclusion groups IP-only and all 200 objects reachable', () => {
  const dir = mkdtempSync(join(tmpdir(), 'cma-fixture-'));
  try {
    const log = join(dir, 'calls');
    writeFileSync(join(dir, 'mgmt_cli'), '#!/bin/sh\nprintf \'%s\\0\' "$@" >> "$FIXTURE_LOG"\nprintf \'\\0\' >> "$FIXTURE_LOG"\n', { mode: 0o700 });
    const preview = execFileSync('bash', [new URL('../scripts/build-test-policy.sh', import.meta.url).pathname,
      '--prefix', 'TEST_FIXTURE', '--seed', '42'], { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
    // Interpret Bash's escaped preview using a recording CLI; no real API calls.
    execFileSync('bash', [], { input: preview, env: { ...process.env, PATH: `${dir}:${process.env.PATH}`, FIXTURE_LOG: log } });
    const calls = readFileSync(log, 'utf8').split('\0\0').filter(Boolean).map(line => {
      const [verb, type, ...args] = line.split('\0');
      const fields = {};
      for (let i = 0; i < args.length; i += 2) fields[args[i]] = args[i + 1];
      return { verb, type, ...fields };
    });
    const adds = calls.filter(c => c.verb === 'add');
    const rules = adds.filter(c => c.type === 'access-rule');
    const objects = new Map(adds.filter(c => !['access-rule', 'access-section', 'access-layer', 'package'].includes(c.type)).map(c => [c.name, c]));
    assert.equal(objects.size, 200);
    assert.equal(rules.length, 100);
    assert.equal(adds.filter(c => c.type === 'access-section').length, 10);
    const refs = object => Object.entries(object).filter(([key]) => /^(members\.|source\.|destination\.|service\.)/.test(key) || ['include', 'except'].includes(key)).map(([, value]) => value);
    const ipOnly = name => {
      const object = objects.get(name);
      assert.ok(object, `Missing object: ${name}`);
      if (object.type === 'group') refs(object).forEach(ipOnly);
      else assert.ok(['host', 'network', 'address-range'].includes(object.type), `Non-IP exclusion member: ${name}`);
    };
    const exclusion = [...objects.values()].find(o => o.type === 'group-with-exclusion');
    ipOnly(exclusion.include);
    ipOnly(exclusion.except);
    const reached = new Set();
    const visit = name => {
      if (name === 'Any' || reached.has(name)) return;
      assert.ok(objects.has(name), `Missing reference: ${name}`);
      reached.add(name);
      refs(objects.get(name)).forEach(visit);
    };
    rules.flatMap(refs).forEach(visit);
    assert.equal(reached.size, 200);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
