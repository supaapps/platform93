"use client";

import { Children, isValidElement, useEffect, useId, useRef, useState, type ReactNode } from "react";
import { Button, ListBox, ListBoxItem, Popover, Select, SelectValue } from "react-aria-components";

type Option = { value: string; label: string; disabled: boolean; group?: string };
function optionsFrom(children: ReactNode, group?: string): Option[] {
  return Children.toArray(children).flatMap((child): Option[] => {
    if (!isValidElement<{ value?: string; label?: string; disabled?: boolean; children?: ReactNode }>(child)) return [];
    if (child.type === "option") {
      const label = Children.toArray(child.props.children).join("");
      return [{ value: String(child.props.value ?? label), label, disabled: !!child.props.disabled, group }];
    }
    return optionsFrom(child.props.children, child.type === "optgroup" ? child.props.label : group);
  });
}

/** Native form names and reset behaviour, with one styled, accessible overlay. */
export function SelectControl({ children, label, value, defaultValue, onValueChange, name, id, disabled = false, required = false, "aria-label": ariaLabel }: {
  children: ReactNode; value?: string; defaultValue?: string; onValueChange?: (value: string) => void;
  label: string;
  name?: string; id?: string; disabled?: boolean; required?: boolean; "aria-label"?: string;
}) {
  const generatedID = useId();
  const root = useRef<HTMLDivElement>(null);
  const native = useRef<HTMLSelectElement>(null);
  const options = optionsFrom(children);
  const [local, setLocal] = useState(defaultValue ?? options[0]?.value ?? "");
  const [fieldsetDisabled, setFieldsetDisabled] = useState(false);
  const [invalid, setInvalid] = useState(false);
  const selected = value ?? local;
  const resetValue = defaultValue ?? options[0]?.value ?? "";
  const triggerID = `${id ?? generatedID}-trigger`;
  const labelID = `${generatedID}-label`;
  useEffect(() => {
    const outerLabel = root.current?.closest("label");
    const associatedLabel = id ? document.querySelector<HTMLLabelElement>(`label[for="${CSS.escape(id)}"]`) : null;
    const source = outerLabel ?? associatedLabel;
    if (source) {
      source.htmlFor = triggerID;
    }
    const fieldset = root.current?.closest("fieldset");
    const observer = new MutationObserver(() => setFieldsetDisabled(!!fieldset?.disabled));
    if (fieldset) { setFieldsetDisabled(fieldset.disabled); observer.observe(fieldset, { attributes: true, attributeFilter: ["disabled"] }); }
    const form = root.current?.closest("form");
    const reset = () => { setLocal(resetValue); setInvalid(false); };
    form?.addEventListener("reset", reset);
    return () => { observer.disconnect(); form?.removeEventListener("reset", reset); };
  }, [resetValue, id, triggerID]);
  return <div ref={root} className="ui-select">
    <span className="ui-visually-hidden" id={labelID}>{ariaLabel ?? label}</span>
    <select ref={native} id={id} className="ui-native-select" aria-hidden="true" tabIndex={-1} name={name} value={selected} disabled={disabled || fieldsetDisabled} required={required}
      onChange={(event) => { setLocal(event.target.value); onValueChange?.(event.target.value); }}
      onInvalid={(event) => { event.preventDefault(); setInvalid(true); document.getElementById(triggerID)?.focus(); }}>
      {children}
    </select>
    <Select aria-labelledby={labelID} selectedKey={selected} isDisabled={disabled || fieldsetDisabled} isRequired={required}
      onSelectionChange={(key) => { if (key !== null) { setLocal(String(key)); setInvalid(false); onValueChange?.(String(key)); } }}>
      <Button id={triggerID} aria-labelledby={labelID} aria-invalid={invalid || undefined} aria-describedby={invalid ? `${generatedID}-error` : undefined} className="ui-select-trigger"><SelectValue>{() => options.find((option) => option.value === selected)?.label ?? "Select option"}</SelectValue> <span className="ui-chevron" aria-hidden="true">⌄</span></Button>
      <Popover className="ui-popover" placement="bottom start" offset={6}>
        <ListBox className="ui-listbox" items={options} disabledKeys={options.filter((option) => option.disabled).map((option) => option.value)}>
          {(option) => <ListBoxItem id={option.value} textValue={option.label} className="ui-option" data-value={option.value}>
            <span>{option.group && <small>{option.group}</small>}{option.label}</span><span className="ui-option-check" aria-hidden="true">✓</span>
          </ListBoxItem>}
        </ListBox>
      </Popover>
    </Select>
    {invalid && <span id={`${generatedID}-error`} className="ui-field-error" role="alert">Choose {label.toLowerCase()}.</span>}
  </div>;
}
