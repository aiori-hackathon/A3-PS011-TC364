import React from 'react';

interface BadgeProps {
  children: React.ReactNode;
  variant?: 'cyan' | 'violet' | 'emerald' | 'amber' | 'rose' | 'slate' | 'outline';
  size?: 'sm' | 'md';
  pulse?: boolean;
}

export const Badge: React.FC<BadgeProps> = ({
  children,
  variant = 'cyan',
  size = 'md',
  pulse = false,
}) => {
  const sizeStyles = {
    sm: 'text-[10px] px-1.5 py-0.5 tracking-wider font-mono',
    md: 'text-xs px-2.5 py-0.5 font-medium',
  };

  const variantStyles = {
    cyan: 'bg-cyan-950/70 text-cyan-400 border border-cyan-500/30 shadow-[0_0_8px_rgba(0,240,255,0.15)]',
    violet: 'bg-violet-950/70 text-violet-400 border border-violet-500/30 shadow-[0_0_8px_rgba(139,92,246,0.15)]',
    emerald: 'bg-emerald-950/70 text-emerald-400 border border-emerald-500/30 shadow-[0_0_8px_rgba(16,185,129,0.15)]',
    amber: 'bg-amber-950/70 text-amber-400 border border-amber-500/30 shadow-[0_0_8px_rgba(245,158,11,0.15)]',
    rose: 'bg-rose-950/70 text-rose-400 border border-rose-500/30 shadow-[0_0_8px_rgba(244,63,94,0.15)]',
    slate: 'bg-navy-800 text-slate-300 border border-navy-600',
    outline: 'border border-navy-600 text-slate-400',
  };

  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full select-none ${sizeStyles[size]} ${variantStyles[variant]}`}>
      {pulse && (
        <span className="relative flex h-1.5 w-1.5">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 bg-current"></span>
          <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-current"></span>
        </span>
      )}
      {children}
    </span>
  );
};
