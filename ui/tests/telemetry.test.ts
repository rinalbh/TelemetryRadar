import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { nextSnapshot, parseSnapshot, totals, UPDATE_INTERVAL_MS, HISTORY_POINTS } from '../src/lib/telemetry/model.ts';

const fixture = () => parseSnapshot(readFileSync(new URL('../src/lib/telemetry/mock-traffic.json', import.meta.url), 'utf8'));

test('JSON fixture has seven applications and a bounded chronological history', () => {
  const snapshot = fixture();
  assert.equal(snapshot.applications.length, 7);
  assert.equal(snapshot.history.length, HISTORY_POINTS);
  assert.equal(snapshot.history.at(-1)?.timestamp, snapshot.timestamp);
});

test('one five-second update synchronizes history, rates and accumulated application volumes', () => {
  const before = fixture();
  const original = JSON.stringify(before);
  const next = nextSnapshot(before, before.timestamp + UPDATE_INTERVAL_MS);
  assert.equal(JSON.stringify(before), original, 'must not mutate the preceding snapshot');
  assert.equal(next.sequence, before.sequence + 1);
  assert.equal(next.history.length, HISTORY_POINTS);
  assert.deepEqual(next.history.at(-1), { timestamp: next.timestamp, ...totals(next.applications) });
  next.applications.forEach((app, index) => {
    assert.equal(app.inputBytes - before.applications[index].inputBytes, app.inputBytesPerSecond * 5);
    assert.equal(app.outputBytes - before.applications[index].outputBytes, app.outputBytesPerSecond * 5);
    assert.notEqual(app.inputBytesPerSecond, before.applications[index].inputBytesPerSecond);
  });
  assert.deepEqual(parseSnapshot(JSON.stringify(next)), next);
});

test('long-running capture keeps only the sliding five-minute window', () => {
  let snapshot = fixture();
  for (let i = 0; i < 720; i++) snapshot = nextSnapshot(snapshot, snapshot.timestamp + UPDATE_INTERVAL_MS);
  assert.equal(snapshot.history.length, HISTORY_POINTS);
  assert.equal(snapshot.history.at(-1)!.timestamp - snapshot.history[0].timestamp, 300_000);
});

test('transport rejects negative traffic, duplicate ids and out-of-order history', () => {
  const negative = fixture(); negative.applications[0].inputBytes = -1;
  assert.throws(() => parseSnapshot(JSON.stringify(negative)));
  const duplicate = fixture(); duplicate.applications[1].id = duplicate.applications[0].id;
  assert.throws(() => parseSnapshot(JSON.stringify(duplicate)));
  const unordered = fixture(); unordered.history[1].timestamp = unordered.history[0].timestamp;
  assert.throws(() => parseSnapshot(JSON.stringify(unordered)));
});
