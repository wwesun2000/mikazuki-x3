"""Install debug-only toggle controls in the project's stopped portable PCSX2.

Run only after the owned emulator exits. This never configures a native port.
The original INI and first session log are retained without replacement.
"""
from pathlib import Path
import hashlib
import json
import re

ROOT = Path(__file__).resolve().parents[1]
CONTROLS = [
    ('Keyboard/F12', 'Circle'), ('Keyboard/F11', 'Up'),
    ('Keyboard/F10', 'Down'), ('Keyboard/F7', 'Start'),
    ('Keyboard/F13', 'Cross'),
    ('Keyboard/F14', 'Left'),
    ('Keyboard/F15', 'Right'),
    ('Keyboard/F16', 'Triangle'),
]


def main():
    config = ROOT / 'local/pcsx2/inis/PCSX2.ini'
    backup = config.with_name('PCSX2.before-debug-macros.ini')
    log = ROOT / 'captures/logs/pcsx2-session-01-emulog.txt'
    report_path = ROOT / 'analysis/debug_controls.json'
    if any(p.exists() for p in (backup, log, report_path)):
        raise ValueError('Debug setup evidence already exists; refusing to overwrite')
    raw = config.read_bytes()
    text = raw.decode('utf-8-sig')
    match = re.search(r'(?ms)^\[Pad1\]\s*\n(.*?)(?=^\[|\Z)', text)
    if not match or not re.search(r'^Type\s*=\s*DualShock2\s*$', match[1], re.M):
        raise ValueError('Expected the verified DualShock2 configuration')
    body = match[1]
    if re.search(r'^Macro[2-8]\w*\s*=', body, re.M):
        raise ValueError('Existing macro would be replaced')
    body = re.sub(r'^Macro1\w*\s*=.*\r?\n', '', body, flags=re.M).rstrip() + '\n'
    for i, (trigger, button) in enumerate(CONTROLS, 1):
        for suffix, value in [('', trigger), ('Binds', button), ('Toggle', 'true'),
                              ('Frequency', '0'), ('Pressure', '1'), ('Deadzone', '0')]:
            body += f'Macro{i}{suffix} = {value}\n'
    updated = text[:match.start(1)] + body + '\n\n' + text[match.end(1):]
    with backup.open('xb') as output:
        output.write(raw)
    # Normalize line endings once, retaining all unrelated configuration values.
    config.write_text(updated.replace('\r\n', '\n'), encoding='utf-8', newline='\r\n')
    with log.open('xb') as output:
        output.write((ROOT / 'local/pcsx2/logs/emulog.txt').read_bytes())
    report = {
        'evidence_id': 'DEBUG-CONTROLS-001',
        'purpose': 'emulator-only keyboard toggle macros for debug input',
        'backup': str(backup.relative_to(ROOT)),
        'original_sha256': hashlib.sha256(raw).hexdigest(),
        'modified_sha256': hashlib.sha256(config.read_bytes()).hexdigest(),
        'controls': [{'macro': i, 'key': k, 'button': b, 'press_again_to_release': True}
                     for i, (k, b) in enumerate(CONTROLS, 1)],
        'native_port_controls': False,
        'original_keyboard_bindings_preserved': True,
        'source': 'https://github.com/PCSX2/pcsx2/blob/v2.8.2/pcsx2/SIO/Pad/Pad.cpp#L592-L706',
    }
    with report_path.open('x', encoding='utf-8') as output:
        json.dump(report, output, ensure_ascii=False, indent=2)
        output.write('\n')
    print('Installed eight debug macros; preserved original configuration and log.')


if __name__ == '__main__':
    main()
