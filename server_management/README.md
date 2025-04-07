# Pcloudy Machines Details (BMAS)

A Flask-based web application for managing and tracking machines, servers, and virtual instances across different environments.

## Features

- User Management with Admin/User roles
- Machine inventory management
- Physical and cloud instance tracking
- Location-based organization
- Search and filter capabilities
- Detailed machine specifications tracking
- Import/Export machine data via CSV
- Pagination and responsive design
- VNC and SSH port management
- Access control tracking

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/BMAS.git
cd BMAS/server_management
```

2. Create and activate virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Configure environment variables:
Create a `.env` file in the root directory:
```
FLASK_APP=app.py
FLASK_ENV=development
SECRET_KEY=your-secret-key
DATABASE_URL=sqlite:///machines.db
```

5. Initialize the database:
```bash
python init_db.py
```

6. Generate test data (optional):
```bash
python scripts/generate_test_data.py
```

7. Run the application:
```bash
python app.py
```

## Default Users

- Admin User:
  - Username: admin
  - Password: admin123

- Regular User:
  - Username: user
  - Password: user123

## Usage

### Admin Features
- Add/Edit/Delete machines
- Manage users
- Import/Export machine data
- View all machine details
- Track machine locations

### User Features
- View machine inventory
- Search and filter machines
- Access machine details

## Machine Properties

- Hostname
- Username
- OS Type/Version
- CPU Details
- RAM Details
- IP Addresses (Private/Public)
- Physical Location
- VNC/SSH Ports
- Cloud Provider URL
- Outside Accessibility
- Custom Remarks

## API Endpoints

### Machine Management
- GET/POST `/admin/dashboard` - View and manage machines
- GET/POST `/admin/machine/add` - Add new machine
- GET/POST `/admin/machine/<id>/edit` - Edit existing machine
- POST `/admin/machine/<id>/delete` - Delete machine

### User Management
- GET/POST `/admin/users` - Manage users
- POST `/admin/user/<id>/edit` - Edit user
- POST `/admin/user/<id>/delete` - Delete user

### Data Import/Export
- GET `/admin/export-machines` - Export machines to CSV
- POST `/admin/import-machines` - Import machines from CSV

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
