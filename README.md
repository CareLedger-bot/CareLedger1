CareLedger — Healthcare Records Management System

Project Overview

CareLedger is a Python and SQLite healthcare-record management prototype designed to explore how technology can improve the organisation, accessibility and protection of medical information.

The project uses fictional patient information and demonstrates software development, database management and cybersecurity concepts.
## Independent Academic Research

I investigated NHS England's Single Patient Record plans, electronic patient-record security, access controls and audit trails.

I compared NHS and ICO guidance with my CareLedger prototype, identifying its limitations and proposing improvements to record-change accountability.

[Read my NHS research report](RESEARCH.md)

## Key Features

* Patient Management: Add, search, view and update patient records.
* Access Control: Different user permissions for administrators, clinicians and viewers.
* Audit Trails: Record when information has been changed and which account made the change.
* Error Handling: Validate information and manage invalid inputs.
* Database Storage: Store and retrieve fictional patient records using SQLite.
* Web Interface: Navigate patient records through a browser-based dashboard.

Technologies Used

* Python
* SQLite
* HTML and CSS
* GitHub for version control and documentation

Testing

The application includes 12 automated tests covering record management, permissions, validation, authentication and security checks.

Test Results: 12 passed, 0 failed in the development environment.

See TEST_RESULTS.md for further information.

Project Screenshots

Running the Application

Requires Python 3.11 or newer.

python app.py

Open http://127.0.0.1:8765/login in your browser.

Limitations

This is an educational prototype, not a real clinical information system. It must only be used with fictional data and is not suitable for storing real medical records.

Development and Learning

This prototype was developed with AI assistance as a programming and software-design learning resource. Reviewing its implementation, testing its functionality and exploring potential improvements provide opportunities to develop knowledge of Python, databases, software testing and information security.
