"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                     HUBTEL SECURITY TOOLS LIBRARY                             ║
║              Integrated Security Assessment Toolkit                           ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║  Organization : GAZE Limited                                                 ║
║  Team         : Security Operations                                            ║
╚═══════════════════════════════════════════════════════════════════════════════╝

This library provides three main tools for security assessments:

1. GAZERecon - Async HTTP reconnaissance and enumeration
2. POCScaffold - Security POC script generator
3. SecurityReporter - Professional report generation (Word/PDF)

Quick Start:
    
    # Reconnaissance
    from app.lib import GAZERecon, Validators, run_recon
    
    async with GAZERecon(token="...") as recon:
        hits = await recon.enumerate_range(
            "https://api.hubtel.com/v1/users/{n}",
            start=1, end=1000,
            validators=[Validators.status_ok]
        )
    
    # POC Generation
    from app.lib import POCScaffold
    
    scaffold = POCScaffold()
    scaffold.generate("idor_test", template="idor", target="api.hubtel.com")
    
    # Report Generation
    from app.lib import SecurityReporter, AssessmentData, FindingData
    
    reporter = SecurityReporter()
    reporter.generate_word(assessment, "report.docx")
    reporter.generate_pdf(assessment, "report.pdf")
"""

# Recon exports
from app.lib.recon import (
    GAZERecon,
    ReconResponse,
    EnumerationResult,
    Validators,
    OutputExporter,
    ConsoleLogger,
    run_recon,
)

# Scaffold exports
from app.lib.scaffold import (
    POCScaffold,
    POCConfig,
)

# Reporter exports
from app.lib.reporter import (
    SecurityReporter,
    WordReportGenerator,
    HTMLReportGenerator,
    ReportConfig,
    AssessmentData,
    FindingData,
)

__all__ = [
    # Recon
    'GAZERecon',
    'ReconResponse',
    'EnumerationResult',
    'Validators',
    'OutputExporter',
    'ConsoleLogger',
    'run_recon',
    # Scaffold
    'POCScaffold',
    'POCConfig',
    # Reporter
    'SecurityReporter',
    'WordReportGenerator',
    'HTMLReportGenerator',
    'ReportConfig',
    'AssessmentData',
    'FindingData',
]

__version__ = '2.0.0'
