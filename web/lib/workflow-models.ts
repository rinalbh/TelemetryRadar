import type { ModelChoice } from './opencode';

export interface AdvertisedModel {
  value: string;
  label: string;
  group: string | null;
}

export interface ModelPicker {
  configId: string;
  name: string;
  currentValue: string;
  choices: AdvertisedModel[];
}

function object(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown> : null;
}

/** Model IDs and provider groups come only from the current ACP session. */
export function advertisedModels(configs: unknown[]): ModelPicker | null {
  for (const raw of configs) {
    const config = object(raw);
    if (!config || config.category !== 'model' || config.type !== 'select'
      || typeof config.id !== 'string' || typeof config.currentValue !== 'string'
      || !Array.isArray(config.options)) continue;
    const choices: AdvertisedModel[] = [];
    const seen = new Set<string>();
    const add = (raw: unknown, group: string | null): void => {
      const option = object(raw);
      if (!option || typeof option.value !== 'string' || typeof option.name !== 'string'
        || seen.has(option.value)) return;
      seen.add(option.value);
      choices.push({ value: option.value, label: option.name, group });
    };
    for (const rawOption of config.options) {
      const option = object(rawOption);
      if (option && Array.isArray(option.options)) {
        for (const child of option.options) add(child, typeof option.name === 'string' ? option.name : null);
      } else add(rawOption, null);
    }
    return { configId: config.id, name: typeof config.name === 'string' ? config.name : 'Model', currentValue: config.currentValue, choices };
  }
  return null;
}

export function selectedModel(picker: ModelPicker | null, value: string): { choice: ModelChoice | null; label: string } {
  if (!picker) return { choice: null, label: 'OpenCode default' };
  const option = picker.choices.find((option) => option.value === value);
  const label = option ? `${option.group ? `${option.group} · ` : ''}${option.label}` : picker.currentValue;
  return { choice: option ? { configId: picker.configId, value: option.value } : null, label };
}
