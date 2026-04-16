"""
GAZE Security Platform - Evidence Service
Secure file upload handling with virus scanning
"""
import os
import uuid
import hashlib
import socket
from typing import Tuple, Optional

import magic
from flask import current_app
from werkzeug.datastructures import FileStorage
import structlog

from app import db
from app.models import Evidence, EvidenceType

logger = structlog.get_logger()

# Allowed MIME types
ALLOWED_MIME_TYPES = {
    'image/png',
    'image/jpeg',
    'image/gif',
    'image/webp',
    'application/pdf',
    'text/plain',
    'text/markdown',
    'text/html',
    'application/json',
    'application/xml',
    'text/xml',
}

# Max file size (25MB)
MAX_FILE_SIZE = 25 * 1024 * 1024


class EvidenceService:
    """Service for secure evidence file handling"""
    
    @staticmethod
    def upload_evidence(
        file: FileStorage,
        finding_id: str,
        user_id: str,
        evidence_type: EvidenceType = EvidenceType.OTHER,
        description: str = None
    ) -> Tuple[Evidence, Optional[str]]:
        """
        Upload and process evidence file.
        
        Args:
            file: Uploaded file
            finding_id: Finding ID to attach to
            user_id: User uploading the file
            evidence_type: Type of evidence
            description: Optional description
        
        Returns:
            (Evidence object, error message or None)
        """
        # Validate file exists
        if not file or not file.filename:
            return None, "No file provided"
        
        # Read file content
        content = file.read()
        file.seek(0)
        
        # Check file size
        if len(content) > MAX_FILE_SIZE:
            return None, f"File too large. Maximum size is {MAX_FILE_SIZE // 1024 // 1024}MB"
        
        # Validate MIME type using magic bytes (not extension)
        detected_mime = magic.from_buffer(content, mime=True)
        if detected_mime not in ALLOWED_MIME_TYPES:
            logger.warning(
                "rejected_file_type",
                detected_mime=detected_mime,
                filename=file.filename
            )
            return None, f"File type not allowed: {detected_mime}"
        
        # Generate secure filename
        file_hash = hashlib.sha256(content).hexdigest()
        stored_filename = f"{uuid.uuid4().hex}_{file_hash[:16]}"
        
        # Add extension based on detected MIME type
        ext_map = {
            'image/png': '.png',
            'image/jpeg': '.jpg',
            'image/gif': '.gif',
            'image/webp': '.webp',
            'application/pdf': '.pdf',
            'text/plain': '.txt',
            'text/markdown': '.md',
            'text/html': '.html',
            'application/json': '.json',
            'application/xml': '.xml',
            'text/xml': '.xml',
        }
        stored_filename += ext_map.get(detected_mime, '')
        
        # Scan for viruses
        scan_status, scan_result = EvidenceService._scan_file(content)
        
        if scan_status == 'infected':
            logger.warning(
                "malware_detected",
                filename=file.filename,
                scan_result=scan_result
            )
            return None, "File appears to be infected with malware"
        
        # Save file
        evidence_path = current_app.config['EVIDENCE_PATH']
        filepath = os.path.join(evidence_path, stored_filename)
        
        with open(filepath, 'wb') as f:
            f.write(content)
        
        # Sanitize original filename
        from app.security import Sanitizer
        safe_filename = Sanitizer.sanitize_filename(file.filename)
        
        # Create evidence record
        evidence = Evidence(
            original_filename=safe_filename,
            stored_filename=stored_filename,
            mime_type=detected_mime,
            file_size=len(content),
            file_hash=file_hash,
            evidence_type=evidence_type,
            description=description,
            scan_status=scan_status,
            scan_result=scan_result,
            finding_id=finding_id,
            uploaded_by_id=user_id
        )
        
        db.session.add(evidence)
        db.session.commit()
        
        logger.info(
            "evidence_uploaded",
            evidence_id=str(evidence.id),
            filename=safe_filename,
            size=len(content),
            mime_type=detected_mime
        )
        
        return evidence, None
    
    @staticmethod
    def _scan_file(content: bytes) -> Tuple[str, Optional[str]]:
        """
        Scan file content for viruses using ClamAV.
        
        Returns:
            (status, result) - status is 'clean', 'infected', 'pending', or 'error'
        """
        clamav_host = current_app.config.get('CLAMAV_HOST', 'clamav')
        clamav_port = current_app.config.get('CLAMAV_PORT', 3310)
        
        try:
            # Connect to ClamAV daemon
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(30)
            sock.connect((clamav_host, clamav_port))
            
            # Send INSTREAM command
            sock.send(b'zINSTREAM\x00')
            
            # Send file in chunks
            chunk_size = 2048
            for i in range(0, len(content), chunk_size):
                chunk = content[i:i + chunk_size]
                size = len(chunk).to_bytes(4, byteorder='big')
                sock.send(size + chunk)
            
            # Send zero-length chunk to end
            sock.send(b'\x00\x00\x00\x00')
            
            # Receive response
            response = sock.recv(1024).decode('utf-8').strip()
            sock.close()
            
            if 'OK' in response:
                return 'clean', None
            elif 'FOUND' in response:
                # Extract virus name
                virus_name = response.split(':')[1].strip().replace(' FOUND', '')
                return 'infected', virus_name
            else:
                return 'error', response
                
        except socket.timeout:
            logger.warning("clamav_timeout")
            return 'pending', 'Scan timeout'
        except ConnectionRefusedError:
            logger.warning("clamav_unavailable")
            return 'pending', 'Scanner unavailable'
        except Exception as e:
            logger.error("clamav_error", error=str(e))
            return 'error', str(e)
    
    @staticmethod
    def get_evidence_path(evidence: Evidence) -> Optional[str]:
        """Get the full path to an evidence file"""
        if not evidence or not evidence.stored_filename:
            return None
        
        evidence_path = current_app.config['EVIDENCE_PATH']
        filepath = os.path.join(evidence_path, evidence.stored_filename)
        
        if not os.path.exists(filepath):
            return None
        
        return filepath
    
    @staticmethod
    def delete_evidence(evidence: Evidence) -> bool:
        """Delete evidence file and record"""
        filepath = EvidenceService.get_evidence_path(evidence)
        
        if filepath and os.path.exists(filepath):
            os.remove(filepath)
        
        db.session.delete(evidence)
        db.session.commit()
        
        logger.info("evidence_deleted", evidence_id=str(evidence.id))
        return True
