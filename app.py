from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from datetime import datetime
import os
import sys
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)

# Database Configuration with fallback to SQLite
try:
    database_url = os.getenv('MYSQL_URL')
    if not database_url:
        print("Warning: MYSQL_URL environment variable is not set. Falling back to SQLite.")
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
    else:
        # Try to connect to MySQL
        app.config['SQLALCHEMY_DATABASE_URI'] = database_url.replace('mysql://', 'mysql+pymysql://')
        
        # Log the connection string (without credentials)
        safe_uri = database_url.replace('mysql://', 'mysql://')
        if '@' in safe_uri:
            # Mask username/password in logs
            parts = safe_uri.split('@')
            masked_uri = 'mysql://***:***@' + parts[1]
            print(f"Connecting to MySQL: {masked_uri}")
        else:
            print(f"Connecting to MySQL (format might be incorrect)")
except Exception as e:
    print(f"Error setting up database connection: {str(e)}")
    print("Falling back to SQLite database.")
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Rest of your models and routes remain the same
# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    upi_id = db.Column(db.String(50), unique=True)
    password_hash = db.Column(db.String(128))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    profile_image = db.Column(db.String(200), default='default.jpg')
    phone = db.Column(db.String(15))
    transactions = db.relationship('Transaction', backref='user', lazy=True)
    events = db.relationship('Event', backref='user', lazy=True)

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Float, nullable=False)
    type = db.Column(db.String(10), nullable=False)  # 'incoming' or 'outgoing'
    description = db.Column(db.String(200))
    category = db.Column(db.String(50))  # New field for transaction category
    date = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    date = db.Column(db.DateTime, nullable=False)
    budget = db.Column(db.Float)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# New Models for Group Functionality
class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    members = db.relationship('GroupMember', backref='group', lazy=True)
    expenses = db.relationship('GroupExpense', backref='group', lazy=True)

class GroupMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, default=False)
    user = db.relationship('User', backref='group_memberships')

class GroupExpense(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    description = db.Column(db.String(200))
    category = db.Column(db.String(50))
    date = db.Column(db.DateTime, default=datetime.utcnow)
    paid_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    split_equally = db.Column(db.Boolean, default=True)
    splits = db.relationship('ExpenseSplit', backref='expense', lazy=True)

class ExpenseSplit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    expense_id = db.Column(db.Integer, db.ForeignKey('group_expense.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    is_paid = db.Column(db.Boolean, default=False)
    user = db.relationship('User', backref='expense_splits')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and bcrypt.check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('index'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))
            
        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username=username, name=name, email=email, password_hash=password_hash)
        try:
            db.session.add(user)
            db.session.commit()
            flash('Registration successful! Please log in.')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            print(f"Error during registration: {str(e)}")
            flash('An error occurred during registration. Please try again.')
            return redirect(url_for('register'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/events-page')
@login_required
def events_page():
    return render_template('events.html')

@app.route('/stats')
@login_required
def stats():
    return render_template('stats.html')

@app.route('/profile-page')
@login_required
def profile_page():
    return render_template('profile.html')

@app.route('/splitter')
@login_required
def splitter():
    return render_template('splitter.html')

@app.route('/groups')
@login_required
def groups_page():
    return render_template('groups.html')

@app.route('/transactions')
@login_required
def transactions():
    return render_template('transactions.html')

@app.route('/api/users/search')
@login_required
def search_users():
    query = request.args.get('q', '').lower()
    if len(query) < 2:
        return jsonify([])
    
    users = User.query.filter(
        (User.username.ilike(f'%{query}%')) |
        (User.name.ilike(f'%{query}%'))
    ).limit(10).all()
    
    return jsonify([{
        'id': user.id,
        'username': user.username,
        'name': user.name
    } for user in users])

# API Routes
@app.route('/api/transactions', methods=['GET', 'POST'])
@login_required
def transactions_page():
    if request.method == 'POST':
        data = request.json
        transaction = Transaction(
            amount=data['amount'],
            type=data['type'],
            description=data.get('description', ''),
            category=data.get('category', ''),
            user_id=current_user.id
        )
        db.session.add(transaction)
        db.session.commit()
        return jsonify({'message': 'Transaction added successfully'})
    
    transactions = Transaction.query.filter_by(user_id=current_user.id).all()
    return jsonify([{
        'id': t.id,
        'amount': t.amount,
        'type': t.type,
        'description': t.description,
        'category': t.category,
        'date': t.date.strftime('%Y-%m-%d %H:%M:%S')
    } for t in transactions])

@app.route('/api/events', methods=['GET', 'POST'])
@login_required
def events():
    if request.method == 'POST':
        data = request.json
        event = Event(
            name=data['name'],
            date=datetime.strptime(data['date'], '%Y-%m-%d'),
            user_id=current_user.id
        )
        db.session.add(event)
        db.session.commit()
        return jsonify({'message': 'Event added successfully'})
    
    events = Event.query.filter_by(user_id=current_user.id).all()
    return jsonify([{
        'id': e.id,
        'name': e.name,
        'date': e.date.strftime('%Y-%m-%d')
    } for e in events])

@app.route('/api/profile', methods=['GET', 'PUT'])
@login_required
def profile():
    if request.method == 'PUT':
        data = request.json
        user = current_user
        user.name = data.get('name', user.name)
        user.email = data.get('email', user.email)
        user.upi_id = data.get('upi_id', user.upi_id)
        user.phone = data.get('phone', user.phone)
        
        db.session.commit()
        return jsonify({'message': 'Profile updated successfully'})
    
    return jsonify({
        'username': current_user.username,
        'name': current_user.name,
        'email': current_user.email,
        'upi_id': current_user.upi_id,
        'phone': current_user.phone,
        'profile_image': current_user.profile_image,
        'created_at': current_user.created_at.strftime('%Y')
    })

@app.route('/api/change-password', methods=['POST'])
@login_required
def change_password():
    data = request.json
    if bcrypt.check_password_hash(current_user.password_hash, data['current_password']):
        current_user.password_hash = bcrypt.generate_password_hash(data['new_password']).decode('utf-8')
        db.session.commit()
        return jsonify({'message': 'Password changed successfully'})
    return jsonify({'error': 'Current password is incorrect'}), 400

@app.route('/api/balance', methods=['GET'])
@login_required
def get_balance():
    user_transactions = Transaction.query.filter_by(user_id=current_user.id).all()
    total_balance = 0
    
    for transaction in user_transactions:
        if transaction.type == 'income':
            total_balance += transaction.amount
        else:  # expense
            total_balance -= transaction.amount
            
    return jsonify({
        'balance': total_balance,
        'formatted_balance': f"₹{total_balance:,.2f}"
    })

@app.route('/api/transactions/<int:transaction_id>', methods=['PUT', 'DELETE'])
@login_required
def update_transaction(transaction_id):
    transaction = Transaction.query.get_or_404(transaction_id)
    
    # Verify that the transaction belongs to the current user
    if transaction.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    if request.method == 'PUT':
        data = request.json
        transaction.amount = data.get('amount', transaction.amount)
        transaction.type = data.get('type', transaction.type)
        transaction.description = data.get('description', transaction.description)
        transaction.category = data.get('category', transaction.category)
        
        db.session.commit()
        return jsonify({'message': 'Transaction updated successfully'})
    
    elif request.method == 'DELETE':
        db.session.delete(transaction)
        db.session.commit()
        return jsonify({'message': 'Transaction deleted successfully'})

# Group Routes
@app.route('/api/groups', methods=['GET', 'POST'])
@login_required
def groups():
    if request.method == 'POST':
        data = request.json
        group = Group(
            name=data['name'],
            description=data.get('description', ''),
            created_by=current_user.id
        )
        db.session.add(group)
        
        # Add creator as admin member
        member = GroupMember(
            group=group,
            user_id=current_user.id,
            is_admin=True
        )
        db.session.add(member)
        
        # Add other members if provided
        if 'members' in data:
            for member_id in data['members']:
                if member_id != current_user.id:
                    member = GroupMember(
                        group=group,
                        user_id=member_id,
                        is_admin=False
                    )
                    db.session.add(member)
        
        db.session.commit()
        return jsonify({'message': 'Group created successfully', 'group_id': group.id})
    
    # GET request - return all groups where user is a member
    groups = Group.query.join(GroupMember).filter(GroupMember.user_id == current_user.id).all()
    return jsonify([{
        'id': g.id,
        'name': g.name,
        'description': g.description,
        'created_at': g.created_at.strftime('%Y-%m-%d %H:%M:%S'),
        'member_count': len(g.members),
        'created_by': g.created_by
    } for g in groups])

@app.route('/api/groups/<int:group_id>', methods=['GET', 'PUT', 'DELETE'])
@login_required
def group_detail(group_id):
    group = Group.query.get_or_404(group_id)
    member = GroupMember.query.filter_by(group_id=group_id, user_id=current_user.id).first()
    
    if not member:
        return jsonify({'error': 'You are not a member of this group'}), 403
    
    if request.method == 'PUT':
        if not member.is_admin:
            return jsonify({'error': 'Only admins can update group details'}), 403
        
        data = request.json
        group.name = data.get('name', group.name)
        group.description = data.get('description', group.description)
        db.session.commit()
        return jsonify({'message': 'Group updated successfully'})
    
    elif request.method == 'DELETE':
        if not member.is_admin:
            return jsonify({'error': 'Only admins can delete the group'}), 403
        
        db.session.delete(group)
        db.session.commit()
        return jsonify({'message': 'Group deleted successfully'})
    
    # GET request
    return jsonify({
        'id': group.id,
        'name': group.name,
        'description': group.description,
        'created_at': group.created_at.strftime('%Y-%m-%d %H:%M:%S'),
        'created_by': group.created_by,
        'members': [{
            'id': m.user.id,
            'username': m.user.username,
            'name': m.user.name,
            'is_admin': m.is_admin
        } for m in group.members],
        'expenses': [{
            'id': e.id,
            'amount': e.amount,
            'description': e.description,
            'category': e.category,
            'date': e.date.strftime('%Y-%m-%d %H:%M:%S'),
            'paid_by': User.query.get(e.paid_by).username,
            'split_equally': e.split_equally,
            'splits': [{
                'user_id': s.user_id,
                'username': User.query.get(s.user_id).username,
                'amount': s.amount,
                'is_paid': s.is_paid
            } for s in e.splits]
        } for e in group.expenses]
    })

@app.route('/api/groups/<int:group_id>/expenses', methods=['GET', 'POST'])
@login_required
def group_expenses(group_id):
    try:
        # Get the group
        group = Group.query.get_or_404(group_id)
        
        # Verify user is a member of the group
        member = GroupMember.query.filter_by(
            group_id=group_id,
            user_id=current_user.id
        ).first()
        
        if not member:
            return jsonify({'error': 'You are not a member of this group'}), 403

        if request.method == 'POST':
            # Ensure the request is JSON
            if not request.is_json:
                return jsonify({'error': 'Request must be JSON'}), 400

            data = request.get_json()
            if not data:
                return jsonify({'error': 'No data provided'}), 400

            # Validate required fields
            required_fields = ['amount', 'description', 'category']
            for field in required_fields:
                if field not in data:
                    return jsonify({'error': f'Missing required field: {field}'}), 400

            # Create the expense
            expense = GroupExpense(
                group_id=group_id,
                amount=float(data['amount']),
                description=data['description'],
                category=data['category'],
                date=datetime.utcnow(),
                paid_by=current_user.id,
                split_equally=data.get('split_equally', True)
            )
            db.session.add(expense)
            db.session.flush()  # Get the expense ID

            # Create splits
            if data.get('split_equally', True):
                # Get all group members
                group_members = GroupMember.query.filter_by(group_id=group_id).all()
                if not group_members:
                    return jsonify({'error': 'No members found in the group'}), 400

                # Calculate split amount
                split_amount = float(data['amount']) / len(group_members)
                
                # Create splits for each member
                for group_member in group_members:
                    split = ExpenseSplit(
                        expense_id=expense.id,
                        user_id=group_member.user_id,
                        amount=split_amount,
                        is_paid=(group_member.user_id == current_user.id)
                    )
                    db.session.add(split)
            else:
                # Use custom splits
                custom_splits = data.get('custom_splits', {})
                if not custom_splits:
                    return jsonify({'error': 'Custom splits must be provided when split_equally is false'}), 400

                total_split = sum(float(amount) for amount in custom_splits.values())
                
                if abs(total_split - float(data['amount'])) > 0.01:  # Allow for small floating point differences
                    return jsonify({'error': 'Custom splits must sum to the total amount'}), 400
                
                for user_id, amount in custom_splits.items():
                    split = ExpenseSplit(
                        expense_id=expense.id,
                        user_id=int(user_id),
                        amount=float(amount),
                        is_paid=(int(user_id) == current_user.id)
                    )
                    db.session.add(split)

            db.session.commit()
            return jsonify({
                'message': 'Expense added successfully',
                'expense_id': expense.id
            })

        # GET request - return all expenses for the group, sorted by date (newest first)
        expenses = GroupExpense.query.filter_by(group_id=group_id).order_by(GroupExpense.date.desc()).all()
        return jsonify([{
            'id': expense.id,
            'amount': expense.amount,
            'description': expense.description,
            'category': expense.category,
            'date': expense.date.isoformat(),
            'paid_by': User.query.get(expense.paid_by).username,
            'splits': [{
                'user_id': split.user_id,
                'username': User.query.get(split.user_id).username,
                'amount': split.amount,
                'is_paid': split.is_paid
            } for split in expense.splits]
        } for expense in expenses])

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/groups/<int:group_id>/members', methods=['GET', 'POST', 'DELETE'])
@login_required
def group_members(group_id):
    group = Group.query.get_or_404(group_id)
    member = GroupMember.query.filter_by(group_id=group_id, user_id=current_user.id).first()
    
    if not member:
        return jsonify({'error': 'You are not a member of this group'}), 403
    
    if request.method == 'POST':
        if not member.is_admin:
            return jsonify({'error': 'Only admins can add members'}), 403
        
        data = request.json
        user_id = data['user_id']
        
        # Check if user exists
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Check if user is already a member
        existing_member = GroupMember.query.filter_by(group_id=group_id, user_id=user_id).first()
        if existing_member:
            return jsonify({'error': 'User is already a member'}), 400
        
        new_member = GroupMember(
            group_id=group_id,
            user_id=user_id,
            is_admin=data.get('is_admin', False)
        )
        db.session.add(new_member)
        db.session.commit()
        return jsonify({'message': 'Member added successfully'})
    
    elif request.method == 'DELETE':
        if not member.is_admin:
            return jsonify({'error': 'Only admins can remove members'}), 403
        
        user_id = request.json.get('user_id')
        if not user_id:
            return jsonify({'error': 'User ID is required'}), 400
        
        member_to_remove = GroupMember.query.filter_by(group_id=group_id, user_id=user_id).first()
        if not member_to_remove:
            return jsonify({'error': 'Member not found'}), 404
        
        db.session.delete(member_to_remove)
        db.session.commit()
        return jsonify({'message': 'Member removed successfully'})
    
    # GET request
    members = GroupMember.query.filter_by(group_id=group_id).all()
    return jsonify([{
        'id': m.user.id,
        'username': m.user.username,
        'name': m.user.name,
        'is_admin': m.is_admin,
        'joined_at': m.joined_at.strftime('%Y-%m-%d %H:%M:%S')
    } for m in members])

@app.route('/api/groups/<int:group_id>/settle', methods=['POST'])
@login_required
def settle_group(group_id):
    try:
        data = request.get_json()
        settlements = data.get('settlements', [])
        
        # Get the group
        group = Group.query.get_or_404(group_id)
        
        # Verify user is a member of the group
        member = GroupMember.query.filter_by(
            group_id=group_id,
            user_id=current_user.id
        ).first()
        
        if not member:
            return jsonify({'error': 'You are not a member of this group'}), 403
        
        # Create settlement expenses
        for settlement in settlements:
            # Get user IDs for from and to users
            from_user = User.query.filter_by(username=settlement['from']).first()
            to_user = User.query.filter_by(username=settlement['to']).first()
            
            if not from_user or not to_user:
                return jsonify({'error': 'Invalid user in settlement'}), 400
            
            # Create the expense
            expense = GroupExpense(
                group_id=group_id,
                amount=settlement['amount'],
                description=f"Settlement: {settlement['from']} → {settlement['to']}",
                category='Settlement',
                date=datetime.utcnow(),
                paid_by=from_user.id,
                split_equally=False
            )
            db.session.add(expense)
            db.session.flush()  # Get the expense ID
            
            # Create the splits
            split = ExpenseSplit(
                expense_id=expense.id,
                user_id=to_user.id,
                amount=settlement['amount'],
                is_paid=True
            )
            db.session.add(split)
        
        db.session.commit()
        return jsonify({'message': 'Settlement recorded successfully'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/groups/<int:group_id>/leave', methods=['POST'])
@login_required
def leave_group(group_id):
    try:
        # Get the group
        group = Group.query.get_or_404(group_id)
        
        # Verify user is a member of the group
        member = GroupMember.query.filter_by(
            group_id=group_id,
            user_id=current_user.id
        ).first()
        
        if not member:
            return jsonify({'error': 'You are not a member of this group'}), 403
        
        # Check if user is the last admin
        if member.is_admin:
            other_admins = GroupMember.query.filter(
                GroupMember.group_id == group_id,
                GroupMember.user_id != current_user.id,
                GroupMember.is_admin == True
            ).count()
            
            if other_admins == 0:
                return jsonify({'error': 'You are the last admin. Please assign another admin before leaving.'}), 400
        
        # Remove the member
        db.session.delete(member)
        db.session.commit()
        
        return jsonify({'message': 'Successfully left the group'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/stats')
@login_required
def get_stats():
    # Get all transactions for the current user
    transactions = Transaction.query.filter_by(user_id=current_user.id).all()
    
    # Get all group expenses where the user is a member and their share
    group_expenses = db.session.query(GroupExpense, ExpenseSplit)\
        .join(ExpenseSplit, GroupExpense.id == ExpenseSplit.expense_id)\
        .join(GroupMember, GroupExpense.group_id == GroupMember.group_id)\
        .filter(GroupMember.user_id == current_user.id)\
        .filter(ExpenseSplit.user_id == current_user.id)\
        .all()
    
    # Calculate totals
    total_balance = 0
    total_incoming = 0
    total_outgoing = 0
    total_group_outgoing = 0

    # Calculate personal transactions
    for t in transactions:
        if t.type == 'incoming':
            total_incoming += t.amount
            total_balance += t.amount
        else:  # outgoing
            total_outgoing += t.amount
            total_balance -= t.amount
    
    # Calculate group expenses (user's share only)
    for _, split in group_expenses:
        total_group_outgoing += split.amount
        total_outgoing += split.amount  # Add to total outgoing
        total_balance -= split.amount
    
    # Calculate category-wise totals
    category_totals = {}
    for t in transactions:
        category = t.category or 'Uncategorized'
        if category not in category_totals:
            category_totals[category] = {'incoming': 0, 'outgoing': 0, 'group_outgoing': 0}
        category_totals[category][t.type] += t.amount
    
    # Add user's share of group expenses to category totals
    for expense, split in group_expenses:
        category = expense.category or 'Uncategorized'
        if category not in category_totals:
            category_totals[category] = {'incoming': 0, 'outgoing': 0, 'group_outgoing': 0}
        category_totals[category]['group_outgoing'] += split.amount
    
    # Calculate monthly totals
    monthly_totals = {}
    for t in transactions:
        month = t.date.strftime('%Y-%m')
        if month not in monthly_totals:
            monthly_totals[month] = {'incoming': 0, 'outgoing': 0, 'group_outgoing': 0}
        monthly_totals[month][t.type] += t.amount
    
    # Add user's share of group expenses to monthly totals
    for expense, split in group_expenses:
        month = expense.date.strftime('%Y-%m')
        if month not in monthly_totals:
            monthly_totals[month] = {'incoming': 0, 'outgoing': 0, 'group_outgoing': 0}
        monthly_totals[month]['group_outgoing'] += split.amount
    
    # Get recent transactions (last 5)
    recent_transactions = Transaction.query.filter_by(user_id=current_user.id)\
        .order_by(Transaction.date.desc())\
        .limit(5)\
        .all()
    
    # Get recent group expenses where user has a share (last 5)
    recent_group_expenses = db.session.query(GroupExpense, ExpenseSplit)\
        .join(ExpenseSplit, GroupExpense.id == ExpenseSplit.expense_id)\
        .join(GroupMember, GroupExpense.group_id == GroupMember.group_id)\
        .filter(GroupMember.user_id == current_user.id)\
        .filter(ExpenseSplit.user_id == current_user.id)\
        .order_by(GroupExpense.date.desc())\
        .limit(5)\
        .all()
    
    # Combine and sort recent transactions
    all_recent_transactions = []
    for t in recent_transactions:
        all_recent_transactions.append({
            'id': t.id,
            'amount': t.amount,
            'type': t.type,
            'description': t.description,
            'category': t.category,
            'date': t.date.strftime('%Y-%m-%d %H:%M:%S'),
            'is_group': False
        })
    
    for expense, split in recent_group_expenses:
        all_recent_transactions.append({
            'id': expense.id,
            'amount': split.amount,  # Only include user's share
            'type': 'outgoing',
            'description': f"Group: {expense.description} (Your share)",
            'category': expense.category,
            'date': expense.date.strftime('%Y-%m-%d %H:%M:%S'),
            'is_group': True
        })
    
    # Sort by date
    all_recent_transactions.sort(key=lambda x: x['date'], reverse=True)
    
    return jsonify({
        'total_balance': total_balance,
        'total_incoming': total_incoming,
        'total_outgoing': total_outgoing,
        'total_group_outgoing': total_group_outgoing,
        'category_totals': category_totals,
        'monthly_totals': monthly_totals,
        'recent_transactions': all_recent_transactions[:5]
    })

def create_tables():
    try:
        db.create_all()
        print("Database tables created successfully.")
    except Exception as e:
        print(f"Error creating database tables: {str(e)}")

# Use Flask 2.x approach with app context
with app.app_context():
    create_tables()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 5000)), debug=False)