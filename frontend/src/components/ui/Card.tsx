import React from 'react';

interface CardProps {
  children: React.ReactNode;
  className?: string;
  glow?: boolean;
  hover?: boolean;
  onClick?: () => void;
}

export const Card: React.FC<CardProps> = ({
  children,
  className = '',
  glow = false,
  hover = false,
  onClick,
}) => {
  return (
    <div
      onClick={onClick}
      className={`rounded-xl bg-navy-800/80 backdrop-blur-md border border-navy-600/80 p-5 shadow-card-subtle transition-all duration-200 ${
        glow ? 'border-cyan-500/30 shadow-glow-cyan-sm' : ''
      } ${hover ? 'hover:border-navy-500 hover:bg-navy-800' : ''} ${className}`}
    >
      {children}
    </div>
  );
};
