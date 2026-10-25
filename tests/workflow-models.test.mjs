// Run with: node --experimental-strip-types --test tests/workflow-models.test.mjs
// Pure UI contracts; no capture, ACP connection, provider request, or browser.
import test from 'node:test';
import assert from 'node:assert/strict';
import { advertisedModels, selectedModel } from '../web/lib/workflow-models.ts';
import { formatBytes, formatRate, formatDuration } from '../web/lib/workflow-format.ts';

test('model selection follows advertised category and provider groups rather than a literal option ID', () => {
  const picker = advertisedModels([
    { id: 'model', category: 'mode', type: 'select', currentValue: 'edit', options: [{ value: 'edit', name: 'Edit mode' }] },
    { id: 'provider-model-choice', category: 'model', type: 'select', currentValue: 'provider/a', name: 'Analysis model', options: [
      { group: 'provider', name: 'Configured provider', options: [{ value: 'provider/a', name: 'Model A' }, { value: 'provider/b', name: 'Model B' }] },
    ] },
  ]);
  assert.equal(picker.configId, 'provider-model-choice');
  assert.deepEqual(selectedModel(picker, 'provider/b'), {
    choice: { configId: 'provider-model-choice', value: 'provider/b' },
    label: 'Configured provider · Model B',
  });
});

test('flat model options are preserved and unadvertised values never become configuration commands', () => {
  const picker = advertisedModels([{ id: 'pick', category: 'model', type: 'select', currentValue: 'current', options: [
    { value: 'current', name: 'Current model' }, { value: 'other', name: 'Other model' },
  ] }]);
  assert.deepEqual(selectedModel(picker, 'other').choice, { configId: 'pick', value: 'other' });
  assert.deepEqual(selectedModel(picker, 'not-advertised'), { choice: null, label: 'current' });
});

test('missing model capability and malformed advertisements do not invent a picker', () => {
  assert.equal(advertisedModels([null, {}, { id: 'model', category: 'model', type: 'boolean', currentValue: true }]), null);
  assert.deepEqual(selectedModel(null, 'invented/provider'), { choice: null, label: 'OpenCode default' });
});

test('malformed or duplicate choices cannot override a usable advertised value', () => {
  const picker = advertisedModels([{ id: 'pick', category: 'model', type: 'select', currentValue: 'a', options: [
    null, { value: 1, name: 'Invalid' }, { value: 'a', name: 'Model A' },
    { group: 'other', name: 'Other provider', options: [{ value: 'a', name: 'Duplicate' }, { value: 'b', name: 'Model B' }] },
  ] }]);
  assert.equal(picker.choices.length, 2);
  assert.equal(selectedModel(picker, 'a').label, 'Model A');
  assert.equal(selectedModel(picker, 'b').label, 'Other provider · Model B');
});

test('traffic formatting distinguishes verified zero, unavailable measurements, and elapsed time', () => {
  assert.equal(formatBytes(0), '0 B');
  assert.equal(formatBytes(null), 'Unknown');
  assert.equal(formatRate(undefined), 'Unknown');
  assert.equal(formatRate(-1), 'Unknown');
  assert.equal(formatDuration(125_000), '2:05');
  assert.equal(formatDuration(3_661_000), '1:01:01');
});
