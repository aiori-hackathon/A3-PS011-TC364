import React, { useState, useEffect } from 'react';
import {
  ShieldCheck,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  FlaskConical,
  Plus
} from 'lucide-react';
import type { TargetValidationItem } from '../../api/types';
import { api } from '../../api/client';
import { Modal } from '../ui/Modal';
import { Button } from '../ui/Button';

interface ScopeModalProps {
  isOpen: boolean;
  onClose: () => void;
  onScopeCreated: () => void;
}

export const ScopeModal: React.FC<ScopeModalProps> = ({
  isOpen,
  onClose,
  onScopeCreated,
}) => {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [targetsText, setTargetsText] = useState('');
  const [allowLocalLab, setAllowLocalLab] = useState(false);
  const [authorisedConfirmation, setAuthorisedConfirmation] = useState(false);
  const [authorisedBy, setAuthorisedBy] = useState('');

  const [validationItems, setValidationItems] = useState<TargetValidationItem[]>([]);
  const [isValidating, setIsValidating] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Debounced target validation
  useEffect(() => {
    const rawList = targetsText
      .split('\n')
      .map((t) => t.trim())
      .filter(Boolean);

    if (rawList.length === 0) {
      setValidationItems([]);
      return;
    }

    const timer = setTimeout(async () => {
      setIsValidating(true);
      try {
        const resp = await api.validateTargets(rawList, allowLocalLab);
        setValidationItems(resp.items);
      } catch {
        // ignore validation preview errors
      } finally {
        setIsValidating(false);
      }
    }, 400);

    return () => clearTimeout(timer);
  }, [targetsText, allowLocalLab]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);

    if (!name.trim()) {
      setErrorMessage('Scope name is required.');
      return;
    }

    if (!authorisedBy.trim()) {
      setErrorMessage('Authorised By is required (e.g. Audit Lead, CISO, or Ticket ID).');
      return;
    }

    if (!authorisedConfirmation) {
      setErrorMessage('You must confirm explicit authorisation before creating a scope.');
      return;
    }

    const rawTargets = targetsText
      .split('\n')
      .map((t) => t.trim())
      .filter(Boolean);

    if (rawTargets.length === 0) {
      setErrorMessage('At least one target domain or IP is required.');
      return;
    }

    // Check if any validation item failed
    const hasInvalid = validationItems.some((v) => !v.is_valid);
    if (hasInvalid) {
      setErrorMessage('Please fix invalid or blocked targets before submitting.');
      return;
    }

    setIsSubmitting(true);
    try {
      await api.createScope({
        name: name.trim(),
        description: description.trim() || undefined,
        targets: rawTargets,
        allow_local_lab: allowLocalLab,
        authorised_confirmation: authorisedConfirmation,
        authorised_by: authorisedBy.trim(),
      });
      onScopeCreated();
      onClose();
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to create scope.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="Define Authorised Scope"
      subtitle="Establish strict discovery boundaries and verified authorisation"
      maxWidth="xl"
      footer={
        <>
          <Button variant="ghost" size="sm" onClick={onClose} disabled={isSubmitting}>
            Cancel
          </Button>
          <Button
            variant="primary"
            size="sm"
            onClick={handleSubmit}
            loading={isSubmitting}
            icon={<Plus className="w-4 h-4" />}
          >
            Create Scope
          </Button>
        </>
      }
    >
      <form onSubmit={handleSubmit} className="space-y-4">
        {errorMessage && (
          <div className="p-3 rounded-lg bg-rose-950/80 border border-rose-500/50 text-rose-300 text-xs flex items-start gap-2">
            <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
            <span>{errorMessage}</span>
          </div>
        )}

        {/* Scope Name */}
        <div className="space-y-1">
          <label className="text-xs font-semibold text-slate-300 uppercase font-mono">
            Scope Name *
          </label>
          <input
            type="text"
            placeholder="e.g. External Production Web Services"
            value={name}
            onChange={(e) => setName(e.target.value)}
            className="w-full p-2.5 text-xs bg-navy-900 border border-navy-700 rounded-lg text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
            required
          />
        </div>

        {/* Authorised By */}
        <div className="space-y-1">
          <label className="text-xs font-semibold text-slate-300 uppercase font-mono">
            Authorised By (Officer / Ticket Ref) *
          </label>
          <input
            type="text"
            placeholder="e.g. Jane Doe (SecOps Lead) / JIRA-SEC-1049"
            value={authorisedBy}
            onChange={(e) => setAuthorisedBy(e.target.value)}
            className="w-full p-2.5 text-xs bg-navy-900 border border-navy-700 rounded-lg text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
            required
          />
        </div>

        {/* Description */}
        <div className="space-y-1">
          <label className="text-xs font-semibold text-slate-300 uppercase font-mono">
            Description (Optional)
          </label>
          <input
            type="text"
            placeholder="e.g. Public attack surface for quarter 4 penetration testing"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            className="w-full p-2.5 text-xs bg-navy-900 border border-navy-700 rounded-lg text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
          />
        </div>

        {/* Targets Textarea */}
        <div className="space-y-1.5">
          <div className="flex items-center justify-between">
            <label className="text-xs font-semibold text-slate-300 uppercase font-mono">
              Targets (One per line) *
            </label>
            <span className="text-[10px] text-slate-500 font-mono">
              FQDNs or public IPs (No wildcards)
            </span>
          </div>
          <textarea
            rows={4}
            placeholder={`example.com\napi.example.com\nportal.example.com\n93.184.216.34`}
            value={targetsText}
            onChange={(e) => setTargetsText(e.target.value)}
            className="w-full p-2.5 text-xs bg-navy-900 border border-navy-700 rounded-lg text-slate-100 placeholder-slate-500 font-mono focus:outline-none focus:border-cyan-500"
            required
          />
        </div>

        {/* Real-time Target Validation Feedback */}
        {validationItems.length > 0 && (
          <div className="space-y-1.5 p-3 rounded-lg bg-navy-900 border border-navy-750">
            <span className="text-[10px] uppercase font-mono font-bold text-slate-400">
              Live Target Validation & SSRF Check:
            </span>
            <div className="max-h-36 overflow-y-auto space-y-1 pt-1 font-mono text-xs">
              {validationItems.map((item, idx) => (
                <div key={idx} className="flex items-start gap-2">
                  {item.is_valid ? (
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
                  ) : (
                    <XCircle className="w-3.5 h-3.5 text-rose-400 shrink-0 mt-0.5" />
                  )}
                  <div className="flex-1 min-w-0">
                    <span className={item.is_valid ? 'text-slate-200' : 'text-rose-300'}>
                      {item.raw}
                    </span>
                    {item.error && (
                      <div className="text-[10px] text-rose-400 font-sans mt-0.5">
                        {item.error}
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Local Lab Mode Toggle */}
        <div className="p-3.5 rounded-xl bg-navy-900/80 border border-navy-750 space-y-2">
          <label className="flex items-center justify-between cursor-pointer">
            <div className="flex items-center gap-2">
              <FlaskConical className="w-4 h-4 text-violet-400" />
              <div>
                <span className="text-xs font-semibold text-slate-200">
                  Allow Local Lab Targets
                </span>
                <p className="text-[11px] text-slate-400">
                  Enables RFC 1918 private IPs (10.0.0.0/8, 192.168.0.0/16) and loopback for local research.
                </p>
              </div>
            </div>
            <input
              type="checkbox"
              checked={allowLocalLab}
              onChange={(e) => setAllowLocalLab(e.target.checked)}
              className="rounded border-navy-700 text-violet-500 focus:ring-0 bg-navy-950 w-4 h-4"
            />
          </label>
        </div>

        {/* Mandatory Explicit Authorisation Checkbox */}
        <div className="p-3.5 rounded-xl bg-cyan-950/30 border border-cyan-500/40 space-y-2">
          <label className="flex items-start gap-3 cursor-pointer">
            <input
              type="checkbox"
              checked={authorisedConfirmation}
              onChange={(e) => setAuthorisedConfirmation(e.target.checked)}
              className="mt-1 rounded border-cyan-500 text-cyan-400 focus:ring-0 bg-navy-950 w-4 h-4 shrink-0"
              required
            />
            <div className="text-xs text-slate-300 leading-relaxed">
              <span className="font-bold text-cyan-300">
                Authorisation Confirmation (PS-011 Mandate):
              </span>{' '}
              I explicitly confirm that I am authorised in writing to discover and inventory these target assets. I acknowledge that ArgusTrace will only execute bounded, non-destructive discovery probes.
            </div>
          </label>
        </div>
      </form>
    </Modal>
  );
};
