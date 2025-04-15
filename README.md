# MoneyMate - Personal Finance Tracker

[![Python Version](https://img.shields.io/badge/python-3.x-blue.svg)](https://www.python.org/)
[![Flask Version](https://img.shields.io/badge/flask-3.0.2-green.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A web-based personal finance management system that helps users track their expenses, income, and manage their budget effectively. Perfect for both personal finance management and group expense tracking.

## Features

- Transaction Management (Income & Expenses)
- Category-based Expense Tracking
- Statistical Analysis with Charts
- Advanced Group Expense Splitting
  - Create and manage multiple groups
  - Split bills equally or custom ratios
  - Track group balances and settlements
  - Real-time settlement suggestions
- User Profile Management
- Secure User Authentication
- Budget Planning and Tracking

## Prerequisites

- Python 3.x
- MySQL Server
- pip (Python package manager)

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/varshini-1396/moneymate.git
   cd moneymate
   ```

2. Create a virtual environment:

   ```bash
   python -m venv venv
   ```

3. Activate the virtual environment:

   - Windows:
     ```bash
     venv\Scripts\activate
     ```
   - Unix/MacOS:
     ```bash
     source venv/bin/activate
     ```

4. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

5. Configure MySQL Database:
   - Create a MySQL database named 'moneymate'
   - Update the .env file with your MySQL credentials:
     ```
     DATABASE_URL=mysql://username:password@localhost/moneymate
     SECRET_KEY=your_secret_key_here
     ```

## Usage

1. Start the application:

   ```bash
   python app.py
   ```

2. Open your browser and navigate to:
   ```
   http://localhost:5000
   ```

### API Documentation

The application provides the following main endpoints:

- `/` - Home page
- `/login` - User login
- `/register` - User registration
- `/dashboard` - User dashboard
- `/transactions` - Transaction management
- `/statistics` - View transaction statistics and spending analytics
- `/groups` - Group expense management
- `/profile` - User profile management

## Project Structure

```
moneymate/
├── static/          # CSS, JavaScript, and static files
├── templates/       # HTML templates
├── app.py          # Main application file
├── .env            # Environment configuration
├── requirements.txt # Project dependencies
└── README.md       # This file
```

## Technologies Used

- Flask (Python web framework)
- Flask-SQLAlchemy (Database ORM)
- Flask-Login (User authentication)
- Flask-Bcrypt (Password hashing)
- MySQL (Database)
- HTML/CSS
- JavaScript
- Python-dotenv (Environment configuration)
- WTForms (Form handling and validation)
- Gunicorn (Production server)

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

Please make sure to update tests as appropriate and follow the existing code style.

## License

This project is licensed - see the [LICENSE](LICENSE) file for details.

## Acknowledgements

- [Flask](https://flask.palletsprojects.com/) - The web framework used
- [SQLAlchemy](https://www.sqlalchemy.org/) - SQL toolkit and ORM
- [Flask-Login](https://flask-login.readthedocs.io/) - User session management
- [Flask-Bcrypt](https://flask-bcrypt.readthedocs.io/) - Password hashing
- [WTForms](https://wtforms.readthedocs.io/) - Form handling

## Support

If you encounter any issues or have questions, please open an issue in the GitHub repository.

## TODO

- [ ] Add unit tests
- [ ] Implement CI/CD pipeline
- [ ] Add more detailed API documentation
- [ ] Create deployment documentation
- [ ] Add contribution guidelines
