from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, status
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import tempfile
import os
import sys
import json
import sqlite3
from datetime import datetime
import hashlib
import secrets

# Import local scanner modules
from scanner import scan_file
from logger import PIILogger

app = FastAPI(title="PII Scanner Test", version="1.0.0")

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Initialize logger
logger = PIILogger("web_scan_results.jsonl")

# Database setup
def init_db():
    """Initialize SQLite database"""
    conn = sqlite3.connect('pii_scanner.db')
    cursor = conn.cursor()
    
    # Create tables
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS file_uploads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            file_hash TEXT UNIQUE,
            file_size INTEGER,
            file_type TEXT,
            upload_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            ip_address TEXT,
            user_agent TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id INTEGER,
            entity_type TEXT,
            value TEXT,
            confidence REAL,
            classification TEXT,
            start_pos INTEGER,
            end_pos INTEGER,
            scan_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (file_id) REFERENCES file_uploads (id)
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rating INTEGER,
            feedback_text TEXT,
            file_types_tested TEXT,
            user_agent TEXT,
            ip_address TEXT,
            feedback_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()

# Security setup
security = HTTPBasic()

# Admin credentials (use environment variables for production)
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "your-secure-password-here")

def get_current_admin(credentials: HTTPBasicCredentials = Depends(security)):
    """Verify admin credentials"""
    is_username_correct = secrets.compare_digest(credentials.username, ADMIN_USERNAME)
    is_password_correct = secrets.compare_digest(credentials.password, ADMIN_PASSWORD)
    
    if not (is_username_correct and is_password_correct):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

# File processing functions
def extract_text_from_file(file_path: str, filename: str) -> str:
    """Extract text content from various file types"""
    file_ext = os.path.splitext(filename)[1].lower()
    
    try:
        if file_ext in ['.txt', '.md', '.log', '.ini', '.cfg', '.yaml', '.yml']:
            # Plain text files
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        
        elif file_ext == '.csv':
            # CSV files - read as text for PII scanning
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        
        elif file_ext in ['.json', '.xml']:
            # JSON/XML files
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        
        elif file_ext in ['.html', '.htm']:
            # HTML files - extract text content
            try:
                from bs4 import BeautifulSoup
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    soup = BeautifulSoup(f.read(), 'html.parser')
                    return soup.get_text()
            except ImportError:
                # Fallback to raw HTML if BeautifulSoup not available
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    return f.read()
        
        elif file_ext == '.pdf':
            # PDF files
            return extract_text_from_pdf(file_path)
        
        elif file_ext == '.docx':
            # Word documents
            return extract_text_from_docx(file_path)
        
        elif file_ext == '.xlsx':
            # Excel files
            return extract_text_from_xlsx(file_path)
        
        else:
            # Unknown file type - try to read as text
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
                
    except Exception as e:
        return f"Error extracting text from {filename}: {str(e)}"

def extract_text_from_pdf(pdf_path: str) -> str:
    """Extract text from PDF files"""
    try:
        # Try pdfplumber first (better text extraction)
        import pdfplumber
        text = ""
        with pdfplumber.open(pdf_path) as pdf:
            for page in pdf.pages:
                page_text = page.extract_text()
                if page_text:
                    text += page_text + "\n"
        if text.strip():
            return text
    except ImportError:
        pass
    
    try:
        # Fallback to PyPDF2
        import PyPDF2
        text = ""
        with open(pdf_path, 'rb') as file:
            reader = PyPDF2.PdfReader(file)
            for page in reader.pages:
                page_text = page.extract_text()
                if page_text:
                    text += page_text + "\n"
        return text
    except Exception as e:
        return f"Error extracting PDF text: {str(e)}"

def extract_text_from_docx(docx_path: str) -> str:
    """Extract text from Word documents"""
    try:
        from docx import Document
        doc = Document(docx_path)
        text = ""
        for paragraph in doc.paragraphs:
            text += paragraph.text + "\n"
        return text
    except ImportError:
        return "python-docx library not available for .docx files"
    except Exception as e:
        return f"Error extracting DOCX text: {str(e)}"

def extract_text_from_xlsx(xlsx_path: str) -> str:
    """Extract text from Excel files"""
    try:
        import pandas as pd
        # Read all sheets
        excel_file = pd.ExcelFile(xlsx_path)
        text = ""
        for sheet_name in excel_file.sheet_names:
            df = pd.read_excel(xlsx_path, sheet_name=sheet_name)
            text += f"Sheet: {sheet_name}\n"
            text += df.to_string() + "\n\n"
        return text
    except ImportError:
        return "pandas library not available for .xlsx files"
    except Exception as e:
        return f"Error extracting XLSX text: {str(e)}"

def scan_text_content(text: str, filename: str) -> List[Dict[str, Any]]:
    """Scan text content for PII using your existing scanner"""
    try:
        # Create a temporary file with the extracted text
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt', encoding='utf-8') as temp_file:
            temp_file.write(text)
            temp_file.flush()
            
            # Use your existing scanner
            results = scan_file(temp_file.name)
            
            # Clean up temp file
            os.unlink(temp_file.name)
            
            return results
    except Exception as e:
        return [{"entity_type": "ERROR", "value": f"Scan error: {str(e)}", "confidence": 0.0, "classification": "error"}]

# Initialize database on startup
init_db()

@app.get("/", response_class=HTMLResponse)
async def home():
    """Serve the main HTML page"""
    with open("static/index.html", "r") as f:
        return HTMLResponse(content=f.read())

@app.get("/admin", response_class=HTMLResponse)
async def admin(username: str = Depends(get_current_admin)):
    """Serve the admin dashboard (requires authentication)"""
    with open("static/admin.html", "r") as f:
        return HTMLResponse(content=f.read())

@app.post("/upload")
async def upload_file(file: UploadFile = File(...), request=None):
    """Process uploaded file and return PII scan results"""
    try:
        # Security checks
        if file.size and file.size > 10 * 1024 * 1024:  # 10MB limit
            raise HTTPException(status_code=413, detail="File too large. Maximum size is 10MB.")
        
        # Read file content
        content = await file.read()
        
        if len(content) > 10 * 1024 * 1024:  # Double-check size
            raise HTTPException(status_code=413, detail="File too large. Maximum size is 10MB.")
        
        file_hash = hashlib.md5(content).hexdigest()
        
        # Create temporary file
        with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(file.filename)[1]) as temp_file:
            temp_file.write(content)
            temp_file.flush()
            
            # Extract text based on file type
            extracted_text = extract_text_from_file(temp_file.name, file.filename)
            
            # Scan the extracted text
            results = scan_text_content(extracted_text, file.filename)
            
            # Clean up temp file
            os.unlink(temp_file.name)
            
            # Store file info in database
            conn = sqlite3.connect('pii_scanner.db')
            cursor = conn.cursor()
            
            # Insert file upload record
            cursor.execute('''
                INSERT OR IGNORE INTO file_uploads 
                (filename, file_hash, file_size, file_type, ip_address, user_agent)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                file.filename,
                file_hash,
                len(content),
                os.path.splitext(file.filename)[1].lower(),
                request.client.host if request else None,
                request.headers.get('user-agent') if request else None
            ))
            
            # Get file ID
            cursor.execute('SELECT id FROM file_uploads WHERE file_hash = ?', (file_hash,))
            file_id = cursor.fetchone()[0]
            
            # Store scan results
            for result in results:
                cursor.execute('''
                    INSERT INTO scan_results 
                    (file_id, entity_type, value, confidence, classification, start_pos, end_pos)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    file_id,
                    result["entity_type"],
                    result["value"],
                    result["confidence"],
                    result["classification"],
                    result.get("start", 0),
                    result.get("end", 0)
                ))
            
            conn.commit()
            conn.close()
            
            # Categorize results
            controlled_pii = [r for r in results if r["classification"] == "controlled"]
            non_controlled_pii = [r for r in results if r["classification"] == "non-controlled"]
            
            # Log the results (keeping existing logger)
            for result in results:
                logger.log_finding(
                    file_path=file.filename,
                    entity_type=result["entity_type"],
                    value=result["value"],
                    confidence=result["confidence"],
                    classification=result["classification"]
                )
            
            return {
                "filename": file.filename,
                "file_size": len(content),
                "controlled_pii": controlled_pii,
                "non_controlled_pii": non_controlled_pii,
                "total_findings": len(results),
                "processing_time": "completed",
                "timestamp": datetime.now().isoformat(),
                "file_id": file_id
            }
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing file: {str(e)}")

@app.post("/feedback")
async def submit_feedback(feedback_data: dict, request=None):
    """Collect user feedback"""
    try:
        # Store in database
        conn = sqlite3.connect('pii_scanner.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO feedback 
            (rating, feedback_text, file_types_tested, user_agent, ip_address)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            feedback_data.get("rating", 0),
            feedback_data.get("feedback", ""),
            json.dumps(feedback_data.get("file_types", [])),
            feedback_data.get("user_agent", ""),
            request.client.host if request else None
        ))
        
        conn.commit()
        conn.close()
        
        # Also log to file (keeping existing)
        feedback_entry = {
            "timestamp": datetime.now().isoformat(),
            "feedback": feedback_data.get("feedback", ""),
            "rating": feedback_data.get("rating", 0),
            "user_agent": feedback_data.get("user_agent", ""),
            "file_types_tested": feedback_data.get("file_types", []),
            "issues_found": feedback_data.get("issues", [])
        }
        
        with open("feedback.jsonl", "a") as f:
            f.write(json.dumps(feedback_entry) + "\n")
        
        return {"status": "success", "message": "Feedback received"}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error saving feedback: {str(e)}")

@app.get("/stats")
async def get_stats():
    """Get comprehensive statistics about scans"""
    try:
        conn = sqlite3.connect('pii_scanner.db')
        cursor = conn.cursor()
        
        # Get basic stats
        cursor.execute('SELECT COUNT(*) FROM file_uploads')
        total_files = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM scan_results')
        total_pii = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM scan_results WHERE classification = "controlled"')
        controlled_pii = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM scan_results WHERE classification = "non-controlled"')
        non_controlled_pii = cursor.fetchone()[0]
        
        # Get file type breakdown
        cursor.execute('''
            SELECT file_type, COUNT(*) 
            FROM file_uploads 
            GROUP BY file_type 
            ORDER BY COUNT(*) DESC
        ''')
        file_types = dict(cursor.fetchall())
        
        # Get most common PII types
        cursor.execute('''
            SELECT entity_type, COUNT(*) 
            FROM scan_results 
            GROUP BY entity_type 
            ORDER BY COUNT(*) DESC 
            LIMIT 10
        ''')
        pii_types = dict(cursor.fetchall())
        
        # Get recent activity
        cursor.execute('''
            SELECT COUNT(*) 
            FROM file_uploads 
            WHERE upload_timestamp > datetime('now', '-24 hours')
        ''')
        recent_uploads = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            "total_files": total_files,
            "total_pii_found": total_pii,
            "controlled_pii": controlled_pii,
            "non_controlled_pii": non_controlled_pii,
            "file_types": file_types,
            "pii_types": pii_types,
            "recent_uploads_24h": recent_uploads
        }
        
    except Exception as e:
        return {"error": str(e)}

@app.get("/admin/data")
async def get_admin_data(username: str = Depends(get_current_admin)):
    """Get detailed data for analysis (admin endpoint - requires authentication)"""
    try:
        conn = sqlite3.connect('pii_scanner.db')
        cursor = conn.cursor()
        
        # Get all file uploads
        cursor.execute('''
            SELECT id, filename, file_size, file_type, upload_timestamp, ip_address
            FROM file_uploads 
            ORDER BY upload_timestamp DESC
        ''')
        files = [dict(zip(['id', 'filename', 'file_size', 'file_type', 'upload_timestamp', 'ip_address'], row)) 
                for row in cursor.fetchall()]
        
        # Get all scan results
        cursor.execute('''
            SELECT sr.*, fu.filename 
            FROM scan_results sr 
            JOIN file_uploads fu ON sr.file_id = fu.id 
            ORDER BY sr.scan_timestamp DESC
        ''')
        results = [dict(zip(['id', 'file_id', 'entity_type', 'value', 'confidence', 'classification', 
                           'start_pos', 'end_pos', 'scan_timestamp', 'filename'], row)) 
                  for row in cursor.fetchall()]
        
        # Get all feedback
        cursor.execute('''
            SELECT rating, feedback_text, file_types_tested, user_agent, ip_address, feedback_timestamp
            FROM feedback 
            ORDER BY feedback_timestamp DESC
        ''')
        feedback = [dict(zip(['rating', 'feedback_text', 'file_types_tested', 'user_agent', 
                            'ip_address', 'feedback_timestamp'], row)) 
                   for row in cursor.fetchall()]
        
        conn.close()
        
        return {
            "files": files,
            "results": results,
            "feedback": feedback
        }
        
    except Exception as e:
        return {"error": str(e)}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000) 