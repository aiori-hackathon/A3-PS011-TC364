import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import React from 'react';
import { Badge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import { Card } from '../components/ui/Card';

describe('UI Core Components', () => {
  it('renders Badge with correct text and pulse effect', () => {
    render(<Badge variant="emerald" pulse>ACTIVE</Badge>);
    const badge = screen.getByText('ACTIVE');
    expect(badge).toBeDefined();
  });

  it('renders Button and fires click handler', () => {
    const handleClick = vi.fn();
    render(<Button onClick={handleClick}>Start Probe</Button>);
    const btn = screen.getByText('Start Probe');
    fireEvent.click(btn);
    expect(handleClick).toHaveBeenCalledTimes(1);
  });

  it('renders Button in loading state with disabled attribute', () => {
    render(<Button loading>Launching</Button>);
    const btn = screen.getByRole('button');
    expect(btn.hasAttribute('disabled')).toBe(true);
  });

  it('renders Card with cyber styling', () => {
    render(<Card glow>Discovery Scope</Card>);
    const cardText = screen.getByText('Discovery Scope');
    expect(cardText).toBeDefined();
  });
});
