import { describe, it, expect, vi, beforeEach } from 'vitest';
import { api } from '../api/client';

describe('Frontend API Client', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('correctly constructs scope validation request', async () => {
    const mockResponse = {
      items: [
        { raw: 'example.com', sanitized: 'example.com', is_valid: true, error: null }
      ],
      all_valid: true
    };

    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => mockResponse
    } as any);

    const result = await api.validateTargets(['example.com'], false);

    expect(globalThis.fetch).toHaveBeenCalledWith('/api/scopes/validate-targets', expect.objectContaining({
      method: 'POST',
      body: JSON.stringify({ targets: ['example.com'], allow_local_lab: false })
    }));
    expect(result.all_valid).toBe(true);
    expect(result.items[0].is_valid).toBe(true);
  });

  it('handles backend error response with detail field', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 400,
      json: async () => ({ detail: 'Scope lacks verified authorization confirmation flag.' })
    } as any);

    await expect(api.createScope({
      name: 'Test Scope',
      targets: ['example.com'],
      allow_local_lab: false,
      authorised_confirmation: false,
      authorised_by: 'Test Officer'
    })).rejects.toThrow('Scope lacks verified authorization confirmation flag.');
  });
});
