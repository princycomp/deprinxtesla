import smtplib
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import requests
from bson import ObjectId
from flask import Flask, jsonify, request, render_template, url_for, session, flash, redirect
from flask_bcrypt import Bcrypt, generate_password_hash
from flask_mail import Mail, Message
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_wtf.csrf import generate_csrf
from itsdangerous import URLSafeTimedSerializer
from pymongo import MongoClient
from forms import RegistrationForm, LoginForm
from models import get_user_by_id
import logging
from flask_cors import CORS
from flask_jwt_extended import unset_jwt_cookies


app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkdeEfBA6O6donzWlSihBXox7C0sKR6b'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'teslaproinvestmentplatform1@gmail.com'
app.config['MAIL_PASSWORD'] = 'yvvpuxqpaaqtqsed'
app.config['MAIL_DEFAULT_SENDER'] = 'teslaproinvestmentplatform1@gmail.com'
app.config['JWT_SECRET_KEY'] = 'super-secret-jwt-key'
# STORE JWT IN COOKIES
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config["JWT_ACCESS_COOKIE_PATH"] = "/"
app.config["JWT_COOKIE_SECURE"] = True  # True in production (HTTPS)
app.config["JWT_COOKIE_CSRF_PROTECT"] = False  # disable for now
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=7)

MONGO_URI = 'mongodb+srv://pblmtechnologyinnovation:Ok6Wiu6HqTorLOSu@computercloud.99whnwd.mongodb.net/?retryWrites=true&w=majority'
client = MongoClient(MONGO_URI)
app.mongo = client.get_database("teslaproinvestment")
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
CORS(app, resources={r"/*": {"origins": "https://www.emporionexchange.xyz"}})
CORS(app, resources={r"/*": {"origins": "https://teslafinance.vercel.app"}})
CORS(app, resources={r"/*": {"origins": "https://teslafinance.vercel.app"}})
app.config['WTF_CSRF_ENABLED'] = False


class User:
    def __init__(self, user_data):
        self.id = str(user_data['_id'])
        self.username = user_data['username']
        self.email = user_data['email']
        self.whatsapp = user_data['whatsapp']
        self.usdt_trc_balance = user_data.get('usdt_trc_balance', 0)
        self.btc_balance = user_data.get('btc_balance', 0)
        self.eth_balance = user_data.get('eth_balance', 0)
        self.usdt_erc_balance = user_data.get('usdt_erc_balance', 0)
        self.referral_bonus = user_data.get('referral_bonus', 0)
        self.total_deposit = user_data.get('total_deposit', 0)
        self.total_withdrawal = user_data.get('total_withdrawal', 0)
        self.total_profit = user_data.get('total_profit', 0)
        self.total_balance = user_data.get('total_balance', 0)
        self.referral_link = user_data.get('referral_link', f'teslaproinvestmentplatform.com/ref/{self.username}')
        self.is_verified = user_data.get('is_verified', False)


users_collection = app.mongo.db.users_teslaproinvestment


@app.route("/")
def api():
    # Fetch prices from CoinGecko API
    url = 'https://api.coingecko.com/api/v3/simple/price'
    params = {
        'ids': 'bitcoin,ethereum,solana,dogecoin,cardano',
        'vs_currencies': 'usd'
    }
    response = requests.get(url, params=params)
    prices = response.json()
    return render_template("index.html", prices=prices)


@app.route("/register.html")
def registerhtml():
    return render_template("register.html")


@app.route("/investment.html")
def investmenthtml():
    return render_template("investment.html")


@app.route("/login.html")
def loginhtml():
    return render_template("login.html")


@app.route("/withdraw.html")
def withdrawalhtml():
    return render_template("withdraw.html")


@app.route("/dashboard")
@jwt_required()
def dashboardhtml():
    return render_template("dashboard.html")


@app.route("/profile.html")
def profilehtml():
    return render_template("profile.html")


@app.route('/admin/dashboard')
def admin_dashboard():
    users = users_collection.find()
    users_list = list(users)
    print("Users fetched from the database:", users_list)
    return render_template('admin.html', users=users_list)


@app.route('/fetch_users_count', methods=['GET'])
def fetch_users_count():
    try:
        user_count = app.mongo.db.users_teslaproinvestment.count_documents({})
        return jsonify({'user_count': user_count}), 200
    except Exception as e:
        return jsonify({'message': str(e)}), 500


@app.route('/fetch_users', methods=['GET'])
def fetch_users():
    import time
    from bson import ObjectId

    time.sleep(2)  # Simulate a delay for demonstration purposes

    try:
        users = list(app.mongo.db.users_teslaproinvestment.find({}))
        pending_deposits = list(app.mongo.db.deposit_requests.find({'status': 'pending'}))

        # Create a dictionary to map user_id to their pending deposits
        pending_deposits_map = {}
        for deposit in pending_deposits:
            user_id = str(deposit['user_id'])
            if user_id not in pending_deposits_map:
                pending_deposits_map[user_id] = []
            pending_deposits_map[user_id].append(deposit)

        user_data_list = []

        for user in users:
            user_id = str(user['_id'])
            pending_deposit_info = pending_deposits_map.get(user_id, [])

            # Use the first pending deposit if available, else set default values
            if pending_deposit_info:
                pending_deposit = pending_deposit_info[0].get('amount', 0)
                currency = pending_deposit_info[0].get('currency', None)
            else:
                pending_deposit = 0
                currency = None

            user_data = {
                '_id': user_id,
                'username': user.get('username', ''),
                'email': user.get('email', ''),
                'usdt_trc_balance': user.get('usdt_trc_balance', 0),
                'btc_balance': user.get('btc_balance', 0),
                'eth_balance': user.get('eth_balance', 0),
                'usdt_erc_balance': user.get('usdt_erc_balance', 0),
                'pending_deposit': pending_deposit,
                'currency': currency
            }
            user_data_list.append(user_data)

        return jsonify({'users': user_data_list}), 200

    except Exception as e:
        return jsonify({'message': f'An error occurred: {str(e)}'}), 500


@app.route('/delete_user/<user_id>', methods=['GET', 'POST'])
def delete_user(user_id):
    users_collection.delete_one({"_id": ObjectId(user_id)})
    flash('User deleted')
    return redirect(url_for('admin_dashboard'))


@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    form = RegistrationForm()

    form.username.data = data['username']
    form.email.data = data['email']
    form.password.data = data['password']
    form.confirm_password.data = data['confirm_password']
    form.referrer_username.data = data['referrer_username']
    form.whatsapp.data = data["whatsapp"]

    if form.validate():
        existing_user = app.mongo.db.users_teslaproinvestment.find_one({"email": form.email.data})
        if existing_user:
            return jsonify({'message': 'User already exists. Please login.'}), 400

        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        referral_link = f'https://teslaproinvestmentplatform.com/ref/{form.username.data}'
        user_data = {
            "username": form.username.data,
            "email": form.email.data,
            "password": hashed_password,
            "usdt_trc_balance": 0,
            "btc_balance": 0,
            "eth_balance": 0,
            "usdt_erc_balance": 0,
            "referral_bonus": 0,
            "total_deposit": 0,
            "total_withdrawal": 0,
            "total_profit": 0,
            "total_balance": 0,
            "referral_link": referral_link,
            "whatsapp": form.whatsapp.data,
            "referrer_username": form.referrer_username.data,
            "is_verified": False  # Initially set to False
        }
        app.mongo.db.users_teslaproinvestment.insert_one(user_data)

        token = serializer.dumps(form.email.data, salt='email-confirm')
        confirm_url = f'https://teslaproinvestmentplatform.com/api/confirm_email?token={token}'

        html = render_template('email_verification.html', confirm_url=confirm_url, whatsapp=form.whatsapp.data)
        subject = "Please confirm your email"

        send_email(form.email.data, subject, html)

        return jsonify(
            {'message': 'User registered successfully! Please check your email to confirm your account.'}), 201
    else:
        print(form.errors)
        return jsonify({'errors': form.errors}), 400


@app.route('/api/resend_email', methods=['GET'])
@jwt_required()
def resend_email():
    user_id = get_jwt_identity()
    user_data = app.mongo.db.users_teslaproinvestment.find_one({"_id": ObjectId(user_id)})

    if not user_data:
        return jsonify({'message': 'User not found.'}), 404

    email = user_data['email']

    token = serializer.dumps(email, salt='email-confirm')

    confirm_url = f'https://teslaproinvestmentplatform.com/api/confirm_email?token={token}'

    html = render_template('email_verification.html', confirm_url=confirm_url)
    subject = "Please confirm your email"

    send_email(email, subject, html)

    return jsonify({'message': 'Verification email resent successfully.'}), 200


def send_email(to, subject, template):
    msg = Message(subject, recipients=[to], html=template, sender=app.config['MAIL_DEFAULT_SENDER'])
    mail.send(msg)


@app.route('/api/confirm_email', methods=['GET'])
def confirm_email():
    token = request.args.get('token')

    # token = data.get('token')

    if not token:
        return jsonify({'message': 'Token is missing.'}), 400

    try:
        email = serializer.loads(token, salt='email-confirm', max_age=3600)
    except Exception as e:
        return render_template('invalid.html')

    user_data = app.mongo.db.users_teslaproinvestment.find_one({"email": email})
    if user_data:
        app.mongo.db.users_teslaproinvestment.update_one({"email": email}, {"$set": {"is_verified": True}})
        return render_template('confirmation_success.html')
    else:
        return render_template('confirmation_failed.html')


from flask_jwt_extended import set_access_cookies

@app.route('/api/login', methods=['POST'])
def login():
    form = LoginForm()
    data = request.get_json()

    form.email.data = data['email']
    form.password.data = data['password']

    if form.validate():
        user_data = app.mongo.db.users_teslaproinvestment.find_one({"email": form.email.data})

        if user_data and bcrypt.check_password_hash(user_data['password'], form.password.data):

            access_token = create_access_token(identity=str(user_data["_id"]))

            response = jsonify({"message": "Login successful"})
            set_access_cookies(response, access_token)

            return response, 200

    return jsonify({"message": "Invalid email or password"}), 401


@app.route('/api/logout', methods=['POST'])
def logout():
    response = jsonify({"message": "Logged out successfully"})
    unset_jwt_cookies(response)
    return response


@app.route('/api/current_user', methods=['GET'])
@jwt_required()
def current_user_info():
    user_id = get_jwt_identity()
    user_data = app.mongo.db.users_teslaproinvestment.find_one({"_id": ObjectId(user_id)})

    if user_data:
        user = User(user_data)

        # Calculate total_balance dynamically
        total_balance = (
                float(user.usdt_trc_balance) +
                float(user.usdt_erc_balance) +
                float(user.btc_balance) +
                float(user.eth_balance)
        )

        return jsonify({
            'username': user.username,
            'email': user.email,
            'usdt_trc_balance': user.usdt_trc_balance,
            'btc_balance': user.btc_balance,
            'eth_balance': user.eth_balance,
            'usdt_erc_balance': user.usdt_erc_balance,
            'referral_bonus': user.referral_bonus,
            'total_deposit': user.total_deposit,
            'total_withdrawal': user.total_withdrawal,
            'total_profit': user.total_profit,
            'total_balance': total_balance,
            'referral_link': user.referral_link,
            'is_verified': user.is_verified
        }), 200

    return jsonify({'message': 'No user is currently logged in.'}), 400


@app.route('/api/delete_account', methods=['POST'])
@jwt_required()
def delete_account():
    user_id = get_jwt_identity()
    app.mongo.db.users_teslaproinvestment.delete_one({"_id": ObjectId(user_id)})
    return jsonify({'message': 'Account deleted successfully!'}), 200


@app.route('/api/csrf-token', methods=['GET'])
def get_csrf_token():
    token = generate_csrf()
    session['csrf_token'] = token
    return jsonify({'csrf_token': token})


@app.route('/api/check_username', methods=['GET'])
def check_username():
    username = request.args.get('username')
    if not username:
        return jsonify({'message': 'Username is required.'}), 400

    user_data = app.mongo.db.users_teslaproinvestment.find_one({"username": username})
    if user_data:
        return jsonify({'exists': True}), 200
    else:
        return jsonify({'exists': False}), 200

@app.route('/deposit.html')
@jwt_required()
def deposithtml():
    return render_template("deposit.html")

@app.route("/plan.html")
def investplanhtml():
    return render_template("investment.html")

@app.route("/withdraw.html")
def withdrawhtml():
    return render_template("withdraw.html")


@app.route('/api/deposit', methods=['POST'])
@jwt_required()
def deposit():
    try:
        data = request.get_json()
        amount = float(data.get('amount'))
        currency = data.get('currency')

        # Validate request data
        if not amount or not currency:
            return jsonify({'message': 'Amount and currency are required.'}), 400

        user_id = get_jwt_identity()
        user_data = app.mongo.db.users_teslaproinvestment.find_one({"_id": ObjectId(user_id)})

        if user_data:
            # Store deposit request with 'pending' status
            deposit_request = {
                'user_id': user_id,
                'amount': amount,
                'currency': currency,
                'status': 'pending',
                'date': datetime.utcnow()
            }
            app.mongo.db.deposit_requests.insert_one(deposit_request)

            send_deposit_email(user_data['email'], amount, currency)

            return jsonify({'message': 'Deposit request submitted. Awaiting admin approval.'}), 200
        else:
            return jsonify({'message': 'User not found.'}), 404
    except Exception as e:
        return jsonify({'message': f'An error occurred: {str(e)}'}), 500


def send_deposit_email(recipient_email, amount, currency):
    try:
        msg = Message("Deposit Request Submitted", recipients=[recipient_email])
        msg.html = f"""
        <html>
            <head>
                <style>
                    body {{
                        font-family: Arial, sans-serif;
                        background-color: #f4f4f4;
                        margin: 0;
                        padding: 0;
                    }}
                    .container {{
                        max-width: 600px;
                        margin: 0 auto;
                        background-color: #ffffff;
                        padding: 20px;
                        box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                        border-radius: 8px;
                    }}
                    .header {{
                        background-color: #007bff;
                        color: #ffffff;
                        padding: 20px;
                        text-align: center;
                        border-top-left-radius: 8px;
                        border-top-right-radius: 8px;
                    }}
                    .header h1 {{
                        margin: 0;
                        font-size: 24px;
                    }}
                    .content {{
                        padding: 20px;
                        color: #333333;
                        line-height: 1.6;
                    }}
                    .content h2 {{
                        color: #007bff;
                    }}
                    .footer {{
                        text-align: center;
                        padding: 10px;
                        background-color: #f4f4f4;
                        border-bottom-left-radius: 8px;
                        border-bottom-right-radius: 8px;
                    }}
                    .footer p {{
                        margin: 0;
                        color: #777777;
                        font-size: 12px;
                    }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>Tesla Exchange</h1>
                    </div>
                    <div class="content">
                        <h2>Deposit Request Submitted</h2>
                        <p>Dear User,</p>
                        <p>We have received your deposit request of <strong>{amount} {currency.upper()}</strong>.</p>
                        <p>Your request is currently pending approval. You will be notified once the deposit is processed.</p>
                        <p>Thank you for using our service!</p>
                        <p>Best regards,<br>Emporion Exchange Team</p>
                    </div>
                    <div class="footer">
                        <p>&copy; {datetime.utcnow().year} Emporion Exchange. All rights reserved.</p>
                    </div>
                </div>
            </body>
        </html>
        """
        mail.send(msg)
    except Exception as e:
        app.logger.error(f'Failed to send email: {str(e)}')


@app.route('/api/withdraw', methods=['POST'])
@jwt_required()
def withdraw():
    data = request.get_json()
    amount = float(data.get('amount'))
    currency = data.get('currency')

    if not amount or not currency:
        return jsonify({'message': 'Amount and currency are required.'}), 400

    user_id = get_jwt_identity()
    user_data = app.mongo.db.users_teslaproinvestment.find_one({"_id": ObjectId(user_id)})

    if not user_data:
        return jsonify({'message': 'User not found.'}), 404

    balance_key = f'{currency}_balance'
    if balance_key not in user_data:
        return jsonify({'message': 'Invalid currency.'}), 400
    if float(user_data.get(balance_key, 0)) < amount:
        return jsonify({'message': f'Insufficient {currency.upper()} balance.'}), 400

    new_balance = float(user_data[balance_key]) - amount
    new_total_balance = float(user_data['total_balance']) - amount
    app.mongo.db.users_teslaproinvestment.update_one({"_id": ObjectId(user_id)}, {"$set": {balance_key: new_balance}})
    app.mongo.db.users_teslaproinvestment.update_one({"_id": ObjectId(user_id)}, {"$set": {'total_balance': new_total_balance}})

    transaction_data = {
        'user_id': user_id,
        'transaction_type': 'withdrawal_approved',
        'amount': amount,
        'currency': currency,
        'date': datetime.utcnow(),
        'status': 'withdrawal'
    }
    app.mongo.db.transactions_teslaproinvestment.insert_one(transaction_data)

    # Send email to user
    email = user_data['email']
    subject = 'Withdrawal Request Submitted'
    html = render_template('withdrawal_email.html', amount=amount, currency=currency, new_balance=new_balance)

    try:
        send_email(email, subject, html)
    except Exception as e:
        app.logger.error(f"Error sending email: {str(e)}")

    return jsonify(
        {'message': 'Withdrawal request submitted. Awaiting admin approval.', 'new_balance': new_balance}), 200


@app.route('/approve_withdrawal/<user_id>', methods=['POST'])
def approve_withdrawal(user_id):
    try:
        user_data = app.mongo.db.users_teslaproinvestment.find_one({"_id": ObjectId(user_id)})
        if not user_data:
            return jsonify({'message': 'User not found.'}), 404

        pending_withdrawals = list(app.mongo.db.withdrawal_requests.find({"user_id": user_id, "status": "pending"}))

        if not pending_withdrawals:
            return jsonify({'message': 'No pending withdrawals found for the user.'}), 404

        for withdrawal in pending_withdrawals:
            amount = withdrawal['amount']
            currency = withdrawal['currency']

            if currency == 'eth_balance':
                if user_data.get('eth_balance', 0) < amount:
                    return jsonify({'message': 'Insufficient ETH balance for withdrawal.'}), 400
                new_eth_balance = user_data.get('eth_balance', 0) - amount
                app.mongo.db.users_teslaproinvestment.update_one(
                    {"_id": ObjectId(user_id)},
                    {"$set": {
                        'eth_balance': new_eth_balance,
                        'total_withdrawal': user_data.get('total_withdrawal', 0) + amount,
                        'total_balance': user_data.get('total_balance', 0) - amount
                    }}
                )
            elif currency == 'usdt_erc_balance':
                if user_data.get('usdt_erc_balance', 0) < amount:
                    return jsonify({'message': 'Insufficient USDT (ERC20) balance for withdrawal.'}), 400
                new_usdt_erc_balance = user_data.get('usdt_erc_balance', 0) - amount
                app.mongo.db.users_teslaproinvestment.update_one(
                    {"_id": ObjectId(user_id)},
                    {"$set": {
                        'usdt_erc_balance': new_usdt_erc_balance,
                        'total_withdrawal': user_data.get('total_withdrawal', 0) + amount,
                        'total_balance': user_data.get('total_balance', 0) - amount
                    }}
                )
            elif currency == 'btc_balance':
                if user_data.get('btc_balance', 0) < amount:
                    return jsonify({'message': 'Insufficient BTC balance for withdrawal.'}), 400
                new_btc_balance = user_data.get('btc_balance', 0) - amount
                app.mongo.db.users_teslaproinvestment.update_one(
                    {"_id": ObjectId(user_id)},
                    {"$set": {
                        'btc_balance': new_btc_balance,
                        'total_withdrawal': user_data.get('total_withdrawal', 0) + amount,
                        'total_balance': user_data.get('total_balance', 0) - amount
                    }}
                )
            elif currency == 'usdt_trc_balance':
                if user_data.get('usdt_trc_balance', 0) < amount:
                    return jsonify({'message': 'Insufficient USDT (TRC20) balance for withdrawal.'}), 400
                new_usdt_trc_balance = user_data.get('usdt_trc_balance', 0) - amount
                app.mongo.db.users_teslaproinvestment.update_one(
                    {"_id": ObjectId(user_id)},
                    {"$set": {
                        'usdt_trc_balance': new_usdt_trc_balance,
                        'total_withdrawal': user_data.get('total_withdrawal', 0) + amount,
                        'total_balance': user_data.get('total_balance', 0) - amount
                    }}
                )

        app.mongo.db.withdrawal_requests.update_many(
            {"user_id": user_id, "status": "pending"},
            {"$set": {"status": "approved", "approved_date": datetime.utcnow()}}
        )

        for withdrawal in pending_withdrawals:
            transaction_data = {
                'user_id': user_id,
                'transaction_type': 'withdrawal_approved',
                'amount': withdrawal['amount'],
                'currency': withdrawal['currency'],
                'date': datetime.utcnow(),
                'status': 'approved'
            }
            app.mongo.db.transactions_teslaproinvestment.insert_one(transaction_data)

        return jsonify({'message': 'Withdrawal(s) approved successfully.'}), 200

    except Exception as e:
        return jsonify({'message': str(e)}), 500


def send_approval_email(user_email, amount, currency):
    sender_email = "support@teslaxfinance.com"
    receiver_email = user_email
    password = "Teslasupport1."

    message = MIMEMultipart("alternative")
    message["Subject"] = "Deposit Approved"
    message["From"] = sender_email
    message["To"] = receiver_email

    # Render the HTML template with the provided variables
    html = render_template("approval_email.html", amount=amount, currency=currency)

    part1 = MIMEText(html, "html")
    message.attach(part1)

    with smtplib.SMTP("mail.privateemail.com", 465) as server:
        server.starttls()
        server.login(sender_email, password)
        server.sendmail(sender_email, receiver_email, message.as_string())


@app.route('/approve_deposit/<user_id>', methods=['POST'])
def approve_deposit(user_id):
    try:
        user_data = app.mongo.db.users_teslaproinvestment.find_one({"_id": ObjectId(user_id)})
        if not user_data:
            return jsonify({'message': 'User not found.'}), 404

        pending_deposits = list(app.mongo.db.deposit_requests.find({"user_id": user_id, "status": "pending"}))

        if not pending_deposits:
            return jsonify({'message': 'No pending deposits found for the user.'}), 404

        for deposit in pending_deposits:
            amount = deposit['amount']
            currency = deposit['currency']

            if currency == 'eth_balance':
                new_eth_balance = user_data.get('eth_balance', 0) + amount
                app.mongo.db.users_teslaproinvestment.update_one(
                    {"_id": ObjectId(user_id)},
                    {"$set": {
                        'eth_balance': new_eth_balance,
                        'total_deposit': user_data.get('total_deposit', 0) + amount,
                        'total_balance': user_data.get('total_balance', 0) + amount
                    }}
                )
            elif currency == 'usdt_erc_balance':
                new_usdt_erc_balance = user_data.get('usdt_erc_balance', 0) + amount
                app.mongo.db.users_teslaproinvestment.update_one(
                    {"_id": ObjectId(user_id)},
                    {"$set": {
                        'usdt_erc_balance': new_usdt_erc_balance,
                        'total_deposit': user_data.get('total_deposit', 0) + amount,
                        'total_balance': user_data.get('total_balance', 0) + amount
                    }}
                )
            elif currency == 'btc_balance':
                new_btc_balance = user_data.get('btc_balance', 0) + amount
                app.mongo.db.users_teslaproinvestment.update_one(
                    {"_id": ObjectId(user_id)},
                    {"$set": {
                        'btc_balance': new_btc_balance,
                        'total_deposit': user_data.get('total_deposit', 0) + amount,
                        'total_balance': user_data.get('total_balance', 0) + amount
                    }}
                )
            elif currency == 'usdt_trc_balance':
                new_usdt_trc_balance = user_data.get('usdt_trc_balance', 0) + amount
                app.mongo.db.users_teslaproinvestment.update_one(
                    {"_id": ObjectId(user_id)},
                    {"$set": {
                        'usdt_trc_balance': new_usdt_trc_balance,
                        'total_deposit': user_data.get('total_deposit', 0) + amount,
                        'total_balance': user_data.get('total_balance', 0) + amount
                    }}
                )

        app.mongo.db.deposit_requests.update_many(
            {"user_id": user_id, "status": "pending"},
            {"$set": {"status": "approved", "approved_date": datetime.utcnow()}}
        )

        for deposit in pending_deposits:
            transaction_data = {
                'user_id': user_id,
                'transaction_type': 'deposit_approved',
                'amount': deposit['amount'],
                'currency': deposit['currency'],
                'date': datetime.utcnow(),
                'status': 'approved'
            }
            app.mongo.db.transactions_teslaproinvestment.insert_one(transaction_data)

        # Send email to the user
        subject = "Deposit Approved"
        email = user_data['email']
        print(f"email: {email}")
        html = render_template('deposit_approved_email.html')

        send_email(email, subject, html)

        # Update referral bonus
        referrer_id = user_data.get('referrer_id')
        if referrer_id:
            update_referral_bonus(referrer_id)

        return jsonify({'message': 'Deposit(s) approved successfully.'}), 200

    except Exception as e:
        return jsonify({'message': str(e)}), 500


@app.route('/api/transaction_history', methods=['GET'])
@jwt_required()
def transaction_history():
    user_id = get_jwt_identity()
    check_and_close_finished_investments(user_id)
    transactions = list(app.mongo.db.transactions_teslaproinvestment.find({'user_id': user_id}))

    transaction_history = []
    for transaction in transactions:
        transaction_history.append({
            'transaction_id': str(transaction['_id']),
            'transaction_type': transaction['transaction_type'],
            'amount': transaction['amount'],
            'currency': transaction['currency'],
            'date': transaction['date'].isoformat(),
            'status': transaction['status']
        })

    return jsonify({'transaction_history': transaction_history}), 200


@app.route('/api/invest', methods=['POST'])
@jwt_required()
def invest():
    data = request.get_json()
    amount = data.get('amount')
    currency = data.get('currency')
    plan_name = data.get('plan')
    print(f"plan name: {plan_name}")

    if not amount or not currency or not plan_name:
        return jsonify({'message': 'Amount, currency, and plan are required.'}), 400

    user_id = get_jwt_identity()
    user_data = app.mongo.db.users_teslaproinvestment.find_one({"_id": ObjectId(user_id)})

    if not user_data:
        return jsonify({'message': 'User not found.'}), 404

    active_investments = app.mongo.db.investments_teslaproinvestment.find_one({"user_id": user_id, "status": "active"})
    if active_investments:
        return jsonify({
            'message': 'You already have an active investment plan. Please wait until it is completed before starting a new one.'}), 400

    plans = {
        'beginners': {'return': 0.05, 'duration': 3},
        'standard': {'return': 0.08, 'duration': 3},
        'professional': {'return': 0.10, 'duration': 5},
        'advanced': {'return': 0.15, 'duration': 5},
        'special': {'return': 0.20, 'duration': 5},
        'executive': {'return': 0.30, 'duration': 7},
        'ultimate': {'return': 0.40, 'duration': 7}
    }

    investment_plan = plans.get(plan_name.lower())
    if not investment_plan:
        return jsonify({'message': 'Invalid plan.'}), 400

    amount = float(amount)
    return_amount = float(amount) + float(amount * investment_plan['return'])
    end_date = datetime.utcnow() + timedelta(days=investment_plan['duration'])

    # Validate and update user balance
    balance_key = f'{currency}'
    if balance_key not in user_data:
        return jsonify({'message': 'Invalid currency.'}), 400
    if float(user_data[balance_key]) < float(amount):
        return jsonify({'message': f'Insufficient {currency.upper()} balance.'}), 400

    new_balance = float(user_data[balance_key]) - float(amount)
    new_total_balance = float(user_data['total_balance']) - float(amount)
    app.mongo.db.users_teslaproinvestment.update_one({"_id": ObjectId(user_id)}, {"$set": {balance_key: new_balance}})
    app.mongo.db.users_teslaproinvestment.update_one({"_id": ObjectId(user_id)},
                                              {"$set": {'total_balance': new_total_balance}})

    # Insert investment data
    investment_data = {
        'user_id': user_id,
        'amount': float(amount),
        'currency': currency,
        'plan': plan_name,
        'return_amount': return_amount,
        'start_date': datetime.utcnow(),
        'end_date': end_date,
        'status': 'active'
    }
    app.mongo.db.investments_teslaproinvestment.insert_one(investment_data)

    investment_data['_id'] = str(investment_data['_id'])

    return jsonify({'message': f'Investment in {plan_name} plan successful!', 'investment': investment_data}), 201


@app.route('/api/investments', methods=['GET'])
@jwt_required()
def get_investments():
    user_id = get_jwt_identity()
    check_and_close_finished_investments(user_id)
    investments = list(app.mongo.db.investments_teslaproinvestment.find({'user_id': user_id}))
    investment_history = []
    for investment in investments:
        investment_history.append({
            'investment_id': str(investment['_id']),
            'amount': investment['amount'],
            'currency': investment['currency'],
            'plan': investment['plan'],
            'return_amount': investment['return_amount'],
            'start_date': investment['start_date'].isoformat(),
            'end_date': investment['end_date'].isoformat(),
            'status': investment['status']
        })

    return jsonify({'investment_history': investment_history}), 200


@app.route('/api/get_balance', methods=['GET'])
@jwt_required()
def get_balance():
    currency = request.args.get('currency')
    user_id = get_jwt_identity()
    user_data = app.mongo.db.users_teslaproinvestment.find_one({"_id": ObjectId(user_id)})

    if not user_data:
        return jsonify({"message": "User not found"}), 404

    balance = user_data.get(currency, 0)  # Default to 0 if currency is not found
    return jsonify({"balance": balance})


def check_and_close_finished_investments(user_id):
    current_time = datetime.utcnow()
    investments = app.mongo.db.investments_teslaproinvestment.find(
        {"user_id": user_id, "end_date": {"$lte": current_time}, "status": "active"})

    for investment in investments:
        return_amount = investment['return_amount']
        amount_invested = investment['amount']
        currency = investment['currency']
        profit = return_amount - amount_invested

        user_data = app.mongo.db.users_teslaproinvestment.find_one({"_id": ObjectId(user_id)})

        if user_data:
            if currency == 'eth_balance':
                new_balance = user_data.get('eth_balance', 0) + return_amount
                app.mongo.db.users_teslaproinvestment.update_one({"_id": ObjectId(user_id)},
                                                          {"$set": {'eth_balance': new_balance}})
            elif currency == 'usdt_erc_balance':
                new_balance = user_data.get('usdt_erc_balance', 0) + return_amount
                app.mongo.db.users_teslaproinvestment.update_one({"_id": ObjectId(user_id)},
                                                          {"$set": {'usdt_erc_balance': new_balance}})
            elif currency == 'btc_balance':
                new_balance = user_data.get('btc_balance', 0) + return_amount
                app.mongo.db.users_teslaproinvestment.update_one({"_id": ObjectId(user_id)},
                                                          {"$set": {'btc_balance': new_balance}})
            elif currency == 'usdt_trc_balance':
                new_balance = user_data.get('usdt_trc_balance', 0) + return_amount
                app.mongo.db.users_teslaproinvestment.update_one({"_id": ObjectId(user_id)},
                                                          {"$set": {'usdt_trc_balance': new_balance}})
            else:
                continue

            new_total_balance = user_data.get('total_balance', 0) + return_amount
            new_total_profit = user_data.get('total_profit', 0) + profit

            app.mongo.db.users_teslaproinvestment.update_one({"_id": ObjectId(user_id)},
                                                      {"$set": {'total_balance': new_total_balance,
                                                                'total_profit': new_total_profit}})
            app.mongo.db.investments.update_one(
                {"_id": investment['_id']},
                {"$set": {"status": "closed"}}
            )


def update_referral_bonus(referrer_id):
    referrer = app.mongo.db.users_teslaproinvestment.find_one({"_id": ObjectId(referrer_id)})
    if referrer:
        last_deposit = app.mongo.db.transactions_teslaproinvestment.find_one(
            {"user_id": str(referrer_id), "transaction_type": "deposit"},
            sort=[("date", -1)]
        )

        if last_deposit:
            deposit_currency = last_deposit['currency']
            deposit_amount = last_deposit['amount']

            bonus_amount = deposit_amount * 0.05

            balance_field = f"{deposit_currency.lower()}_balance"
            new_currency_balance = referrer[balance_field] + bonus_amount
            new_total_balance = referrer['total_balance'] + bonus_amount

            app.mongo.db.users_teslaproinvestment.update_one(
                {"_id": referrer_id},
                {"$set": {
                    balance_field: new_currency_balance,
                    "total_balance": new_total_balance
                }}
            )

            # Record the referral bonus transaction
            transaction_data = {
                'user_id': str(referrer_id),
                'transaction_type': 'referral_bonus',
                'amount': bonus_amount,
                'currency': deposit_currency,
                'date': datetime.utcnow(),
                'status': 'completed'
            }
            app.mongo.db.transactions_teslaproinvestment.insert_one(transaction_data)
        else:
            print("No deposit transactions found for the referrer.")
    else:
        print("Referrer not found.")


@app.route("/api/update_profile", methods=["PUT"])
@jwt_required()
def update_profile():
    user_id = get_jwt_identity()
    new_email = request.json.get('email')

    if not new_email:
        return jsonify({"msg": "Missing email in request body"}), 400

    # Update user's email in MongoDB
    result = users_collection.update_one(
        {'_id': ObjectId(user_id)},
        {'$set': {'email': new_email}}
    )

    if result.matched_count == 0:
        return jsonify({"msg": "User not found"}), 404

    return jsonify({"msg": "Email updated successfully", "email": new_email}), 200


@app.route("/api/update_password", methods=["PUT"])
@jwt_required()
def update_password():
    user_id = get_jwt_identity()
    new_password = request.json.get('password')

    if not new_password:
        return jsonify({"msg": "Missing password in request body"}), 400

    # Hash the new password
    hashed_password = generate_password_hash(new_password).decode('utf-8')

    # Update user's password in MongoDB
    result = users_collection.update_one(
        {'_id': ObjectId(user_id)},
        {'$set': {'password': hashed_password}}
    )

    if result.matched_count == 0:
        return jsonify({"msg": "User not found"}), 404

    return jsonify({"msg": "Password updated successfully"}), 200


@app.route('/admin/change-password', methods=['POST'])
def admin_change_password():
    data = request.get_json()
    email = data.get('email')
    new_password = data.get('new_password')

    if not email or not new_password:
        return jsonify({'msg': 'Missing email or password'}), 400

    user = users_collection.find_one({'email': email})
    if not user:
        return jsonify({'msg': 'User not found'}), 404

    hashed_pw = generate_password_hash(new_password)
    users_collection.update_one({'email': email}, {'$set': {'password': hashed_pw}})

    return jsonify({'msg': 'Password updated successfully'}), 200


@app.route('/admin/active-investments', methods=['GET'])
def get_active_investments():
    investments = list(app.mongo.db.investments_teslaproinvestment.find({"status": "active"}))
    for inv in investments:
        inv['_id'] = str(inv['_id'])
        inv['start_date'] = inv['start_date'].isoformat()
        inv['end_date'] = inv['end_date'].isoformat()
    return jsonify({"investments": investments}), 200


@app.route('/admin/update-investment/<investment_id>', methods=['PATCH'])
def update_investment(investment_id):
    data = request.get_json()
    new_return = data.get('return_amount')
    if new_return is None:
        return jsonify({"message": "Return amount is required."}), 400
    app.mongo.db.investments_teslaproinvestment.update_one(
        {"_id": ObjectId(investment_id)},
        {"$set": {"return_amount": float(new_return)}}
    )
    return jsonify({"message": "Investment return updated."}), 200


@app.route('/edit_balance_by_email', methods=['POST'])
def edit_balance_by_email():
    try:
        data = request.get_json()
        print("Received data:", data)  # Debug line

        email = data.get('email')
        if not email:
            return jsonify({'msg': 'Email is required'}), 400

        update_fields = {
            'usdt_trc_balance': float(data.get('usdt_trc_balance', 0) or 0),
            'btc_balance': float(data.get('btc_balance', 0) or 0),
            'eth_balance': float(data.get('eth_balance', 0) or 0),
            'usdt_erc_balance': float(data.get('usdt_erc_balance', 0) or 0)
        }

        print("Update fields:", update_fields)  # Debug line

        result = app.mongo.db.users_teslaproinvestment.update_one(
            {'email': email},
            {'$set': update_fields}
        )

        if result.modified_count:
            return jsonify({'msg': 'Balances updated successfully'}), 200
        else:
            return jsonify({'msg': 'No changes made or user not found'}), 404

    except Exception as e:
        import traceback
        traceback.print_exc()  # Print full traceback in terminal
        return jsonify({'msg': f'Server error: {str(e)}'}), 500


if __name__ == '__main__':
    app.run(debug=False)