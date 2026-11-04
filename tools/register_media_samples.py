"""Register actual offline decoder outputs with their source and known limitations."""
from datetime import datetime, timezone
import json
from pathlib import Path
from capture_catalog import register


def main():
    root = Path(__file__).resolve().parent.parent
    report = json.loads((root / 'analysis/media_decode_report.json').read_text(encoding='utf-8'))
    for item in report['results']:
        paths = [(item['log'], 'debug-log', 'captured')]
        if item['output']:
            kind = 'source-video' if item['output'].endswith('.mp4') else 'decoded-image'
            paths.append((item['output'], kind, 'extracted'))
        for relative, kind, status in paths:
            path = root / relative
            result = register(root, relative, kind=kind, status=status,
                              source_sha256=item['source_sha256'], source_asset_id=item['source'],
                              recorded_at=datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat(),
                              language='und', render_settings=dict(decoder=report['tool_version'].splitlines()[0],
                                                                  command=item['command'], validation=item['status']),
                              stage='offline-media-decoding', spoiler='major',
                              description='原盘素材离线解码验证；不是原版或移植版游戏运行录像。',
                              notes='时间取生成文件mtime。' + ('IPU解码日志出现错误，图像仅供调查，不纳入已验收素材。' if item['decoder_errors'] else '样本解码通过，仍待原版画面/颜色/场序对照。'))
            print(relative, result['result'])


if __name__ == '__main__':
    main()
