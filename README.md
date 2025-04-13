# MoneyMate - Personal Finance Tracker

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

## Setup Instructions

1. Create a virtual environment:

   ```
   python -m venv venv
   ```

2. Activate the virtual environment:

   - Windows:
     ```
     venv\Scripts\activate
     ```
   - Unix/MacOS:
     ```
     source venv/bin/activate
     ```

3. Install dependencies:

   ```
   pip install -r requirements.txt
   ```

4. Configure MySQL Database:

   - Create a MySQL database named 'moneymate'
   - Update the .env file with your MySQL credentials:
     ```
     DATABASE_URL=mysql://username:password@localhost/moneymate
     ```

5. Run the application:

   ```
   python app.py
   ```

6. Open your browser and navigate to:
   ```
   http://localhost:5000
   ```

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


## Contributing

Feel free to submit issues and enhancement requests.
