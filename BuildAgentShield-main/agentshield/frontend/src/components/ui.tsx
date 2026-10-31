import {
  ArrowUpRight,
  Check,
  ChevronDown,
  X,
  type LucideIcon,
} from "lucide-react"
import { useEffect, useRef, type ReactNode } from "react"

export function Badge({
  children,
  tone = "neutral",
  dot = false,
}: {
  children: ReactNode
  tone?: string
  dot?: boolean
}) {
  return (
    <span className={`badge ${tone}`}>
      {dot && <i />}
      {children}
    </span>
  )
}
export function Button({
  children,
  onClick,
  variant = "",
  className = "",
  disabled = false,
  type = "button",
}: {
  children: ReactNode
  onClick?: () => void
  variant?: string
  className?: string
  disabled?: boolean
  type?: "button" | "submit"
}) {
  return (
    <button
      type={type}
      className={`button ${variant} ${className}`}
      onClick={onClick}
      disabled={disabled}
    >
      {children}
    </button>
  )
}
export function PageHeading({
  eyebrow,
  title,
  description,
  actions,
}: {
  eyebrow?: string
  title: string
  description: string
  actions?: ReactNode
}) {
  return (
    <div className="page-heading">
      <div>
        {eyebrow && <div className="eyebrow">{eyebrow}</div>}
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      <div className="heading-actions">{actions}</div>
    </div>
  )
}
export function Panel({
  title,
  description,
  action,
  children,
  className = "",
}: {
  title: string
  description?: string
  action?: ReactNode
  children: ReactNode
  className?: string
}) {
  return (
    <section className={`panel ${className}`}>
      <div className="panel-heading">
        <div>
          <h2>{title}</h2>
          {description && <p>{description}</p>}
        </div>
        {action}
      </div>
      {children}
    </section>
  )
}
export function Modal({
  title,
  children,
  onClose,
  wide = false,
}: {
  title: string
  children: ReactNode
  onClose: () => void
  wide?: boolean
}) {
  const dialog = useRef<HTMLElement>(null)
  useEffect(() => {
    const previousFocus = document.activeElement as HTMLElement | null
    const previousOverflow = document.body.style.overflow
    document.body.style.overflow = "hidden"
    const selector =
      'button:not(:disabled), input:not(:disabled), select:not(:disabled), textarea:not(:disabled), [tabindex="0"]'
    const first = dialog.current?.querySelector<HTMLElement>(selector)
    first?.focus()
    function trapFocus(event: KeyboardEvent) {
      if (event.key !== "Tab") return
      const elements = Array.from(
        dialog.current?.querySelectorAll<HTMLElement>(selector) || [],
      )
      const first = elements[0],
        last = elements[elements.length - 1]
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault()
        last?.focus()
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault()
        first?.focus()
      }
    }
    document.addEventListener("keydown", trapFocus)
    return () => {
      document.removeEventListener("keydown", trapFocus)
      document.body.style.overflow = previousOverflow
      previousFocus?.focus()
    }
  }, [])
  return (
    <div className="modal-backdrop" onClick={onClose}>
      <section
        ref={dialog}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        className={`modal ${wide ? "wide" : ""}`}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="modal-header">
          <h2>{title}</h2>
          <button
            className="icon-button"
            aria-label="Close dialog"
            onClick={onClose}
          >
            <X size={20} />
          </button>
        </div>
        {children}
      </section>
    </div>
  )
}
export function Toggle({
  checked,
  onChange,
  label,
  disabled = false,
}: {
  checked: boolean
  onChange: () => void
  label: string
  disabled?: boolean
}) {
  return (
    <button
      role="switch"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      className={`toggle ${checked ? "on" : ""}`}
      onClick={onChange}
    >
      <span>{checked && <Check size={10} />}</span>
    </button>
  )
}
export function Empty({
  title,
  detail,
  icon: Icon,
}: {
  title: string
  detail: string
  icon: LucideIcon
}) {
  return (
    <div className="empty">
      <Icon size={30} />
      <h3>{title}</h3>
      <p>{detail}</p>
    </div>
  )
}
export const toneFor = (decision: string) =>
  ({
    Blocked: "red",
    Allowed: "green",
    Approval: "amber",
    Quarantined: "violet",
    Redacted: "blue",
    Active: "green",
    Disabled: "neutral",
    Pending: "amber",
    Approved: "green",
    Rejected: "red",
  })[decision] || "neutral"
export function ViewLink({
  children = "View all",
  onClick,
}: {
  children?: ReactNode
  onClick: () => void
}) {
  return (
    <button className="text-link" onClick={onClick}>
      {children}
      <ArrowUpRight size={14} />
    </button>
  )
}
export function Select({
  value,
  onChange,
  options,
  label,
}: {
  value: string
  onChange: (value: string) => void
  options: string[]
  label: string
}) {
  return (
    <div className="select-wrap">
      <select
        aria-label={label}
        value={value}
        onChange={(e) => onChange(e.target.value)}
      >
        {options.map((o) => (
          <option key={o}>{o}</option>
        ))}
      </select>
      <ChevronDown size={13} />
    </div>
  )
}
