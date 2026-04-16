#!/usr/bin/env python3
"""
Sandboxed PDF generation service using WeasyPrint.
Runs as an HTTP service accepting HTML content and returning PDF.
"""
import sys
import os
import json
import base64
import tempfile
import traceback
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from io import BytesIO

# Security: Disable external resource loading
os.environ['WEASYPRINT_DLL_DIRECTORIES'] = ''

from weasyprint import HTML, CSS
from weasyprint.text.fonts import FontConfiguration


class PDFGeneratorHandler(BaseHTTPRequestHandler):
    """HTTP handler for PDF generation requests."""
    
    def do_POST(self):
        """Handle PDF generation request."""
        if self.path != '/generate':
            self.send_error(404, 'Not Found')
            return
        
        try:
            # Read request body
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length)
            data = json.loads(body.decode('utf-8'))
            
            html_content = data.get('html', '')
            css_content = data.get('css', '')
            
            if not html_content:
                self.send_error(400, 'Missing HTML content')
                return
            
            # Generate PDF
            pdf_bytes = generate_pdf_from_string(html_content, css_content)
            
            # Send response
            self.send_response(200)
            self.send_header('Content-Type', 'application/pdf')
            self.send_header('Content-Length', len(pdf_bytes))
            self.end_headers()
            self.wfile.write(pdf_bytes)
            
        except json.JSONDecodeError:
            self.send_error(400, 'Invalid JSON')
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            traceback.print_exc()
            self.send_error(500, str(e))
    
    def do_GET(self):
        """Health check endpoint."""
        if self.path == '/health':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"status": "healthy"}')
        else:
            self.send_error(404, 'Not Found')
    
    def log_message(self, format, *args):
        """Suppress default logging."""
        pass


def generate_pdf_from_string(html_content: str, css_content: str = '') -> bytes:
    """
    Generate PDF from HTML string.
    
    Args:
        html_content: HTML content as string
        css_content: Optional CSS content as string
    
    Returns:
        PDF as bytes
    """
    # Configure fonts
    font_config = FontConfiguration()
    
    # Create a custom URL fetcher that blocks all external resources
    def block_external(url):
        """Block all external resource loading for security."""
        return None
    
    # Load HTML (no external resources allowed)
    html = HTML(string=html_content, url_fetcher=block_external)
    
    # Load CSS if provided
    stylesheets = []
    if css_content:
        stylesheets.append(CSS(string=css_content, font_config=font_config))
    
    # Generate PDF to bytes
    pdf_buffer = BytesIO()
    html.write_pdf(
        pdf_buffer,
        stylesheets=stylesheets,
        font_config=font_config,
        optimize_size=('fonts', 'images')
    )
    
    return pdf_buffer.getvalue()


def generate_pdf(html_path: str, output_path: str, css_path: str = None) -> bool:
    """
    Generate PDF from HTML file (CLI mode).
    
    Args:
        html_path: Path to input HTML file
        output_path: Path for output PDF
        css_path: Optional path to CSS file
    
    Returns:
        True if successful, False otherwise
    """
    try:
        # Read files
        html_content = Path(html_path).read_text()
        css_content = Path(css_path).read_text() if css_path else ''
        
        # Generate PDF
        pdf_bytes = generate_pdf_from_string(html_content, css_content)
        
        # Write output
        Path(output_path).write_bytes(pdf_bytes)
        
        return True
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return False


if __name__ == '__main__':
    # If arguments provided, run in CLI mode
    if len(sys.argv) > 1:
        if len(sys.argv) < 3:
            print("Usage: generate_pdf.py <html_path> <output_path> [css_path]")
            sys.exit(1)
        
        html_path = sys.argv[1]
        output_path = sys.argv[2]
        css_path = sys.argv[3] if len(sys.argv) > 3 else None
        
        success = generate_pdf(html_path, output_path, css_path)
        sys.exit(0 if success else 1)
    
    # Otherwise, run as HTTP service
    port = int(os.environ.get('PORT', 8001))
    server = HTTPServer(('0.0.0.0', port), PDFGeneratorHandler)
    print(f"PDF Generator running on port {port}")
    server.serve_forever()
