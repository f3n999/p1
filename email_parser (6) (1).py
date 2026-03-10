import email
import re
import hashlib
from pathlib import Path
from bs4 import BeautifulSoup

class EmailParser:
    def parse(self, filepath):
        if not Path(filepath).exists():
            return {'error': f'Fichier introuvable: {filepath}'}
        try:
            with open(filepath, 'rb') as f:
                msg = email.message_from_binary_file(f)
        except Exception as e:
            return {'error': str(e)}
        
        return {
            'headers': self._get_headers(msg),
            'body': self._get_body(msg),
            'urls': self._get_urls(msg),
            'emails': self._get_emails(msg),
            'ips': self._get_ips(msg),
            'attachments': self._get_attachments(msg),
        }
    
    def _get_headers(self, msg):
        return {k: str(msg.get(k, 'N/A')) 
                for k in ['From', 'To', 'Subject', 'Date', 'Authentication-Results']}
    
    def _get_body(self, msg):
        text, html = [], []
        for part in msg.walk():
            content = self._decode(part)
            if part.get_content_type() == 'text/plain':
                text.append(content)
            elif part.get_content_type() == 'text/html':
                html.append(content)
        return {'text': '\n'.join(text), 'html': '\n'.join(html)}
    
    def _get_urls(self, msg):
        urls = set()
        for part in msg.walk():
            content = self._decode(part)
            if not content: 
                continue
            # Regex
            for url in re.findall(r'https?://[^\s<>"\']+', content):
                urls.add(url.rstrip('.,;:)'))
            # BeautifulSoup sur HTML
            if part.get_content_type() == 'text/html':
                soup = BeautifulSoup(content, 'html.parser')
                for link in soup.find_all('a', href=True):
                    if link['href'].startswith('http'):
                        urls.add(link['href'])
        return list(urls)
    
    def _get_emails(self, msg):
        emails = set()
        regex = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        # Headers
        for h in ['From', 'To', 'Cc', 'Reply-To']:
            if msg.get(h):
                emails.update(re.findall(regex, str(msg.get(h))))
        # Corps
        for part in msg.walk():
            content = self._decode(part)
            if content:
                emails.update(re.findall(regex, content))
        return list(emails)
    
    def _get_ips(self, msg):
        ips = set()
        for h in msg.get_all('Received', []):
            ips.update(re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', str(h)))
        return list(ips)
    
    def _get_attachments(self, msg):
        attachments = []
        dangerous = {'.exe', '.bat', '.scr', '.vbs', '.js'}
        for part in msg.walk():
            filename = part.get_filename()
            if not filename: 
                continue
            payload = part.get_payload(decode=True)
            if not payload: 
                continue
            ext = Path(filename).suffix.lower()
            attachments.append({
                'filename': filename,
                'extension': ext,
                'size': len(payload),
                'sha256': hashlib.sha256(payload).hexdigest(),
                'is_dangerous': ext in dangerous,
            })
        return attachments
    
    def _decode(self, part):
        try:
            p = part.get_payload(decode=True)
            return p.decode('utf-8', errors='ignore') if p else ''
        except:
            return ''
