"""Read-only check of the supplied itch credential and target draft. Never log secrets."""
import json
import os
import urllib.request

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None

def main():
    key = os.environ.get('BUTLER_API_KEY', '').strip()
    if not key:
        raise SystemExit('BUTLER_API_KEY is missing')
    opener = urllib.request.build_opener(NoRedirect)
    def get(path):
        req = urllib.request.Request('https://api.itch.io/'+path,
                                     headers={'Authorization': 'Bearer '+key,
                                              'User-Agent': 'MikazukiX3-release-check'})
        try:
            with opener.open(req, timeout=45) as r:
                data = json.load(r)
            if data.get('errors'):
                raise ValueError('API error')
            return data
        except Exception:
            # Do not print raw response bodies, requests, headers or exceptions.
            raise SystemExit('itch authentication/API check failed at '+path) from None
    profile=get('profile')
    if profile.get('user',{}).get('username','').lower()!='wwesun2000':
        raise SystemExit('Credential does not belong to the expected account')
    games=get('profile/games').get('games',[])
    target=next((g for g in games if g.get('id')==5357914),None)
    if target is None or target.get('url','').rstrip('/')!='https://wwesun2000.itch.io/mikazuki-x3':
        raise SystemExit('Expected project is not accessible to this credential')
    info=get('credentials/info')
    if info.get('scopes'):
        raise SystemExit('Scoped credential: publishing rights need separate review')
    if target.get('published'):
        raise SystemExit('Expected Draft, but project is published; do not upload automatically')
    print('PASS: API authentication; expected account; target project edit visibility; unscoped key; project remains unpublished.')
    print('Read-only check. No files uploaded and no project settings changed.')

if __name__=='__main__':
    main()
