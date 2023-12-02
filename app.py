from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import pytz

app = Flask(__name__)
app.config['SECRET_KEY'] = '54549fa9435f66d31b722b02d67ce3aa977dca103fada46d9dda268d3a16c38f'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///journal.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    # Add more fields for your user as needed

class JournalEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, server_default=db.func.now())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    # Defer the resolution of GuidedJournalResponse using a string
    guided_responses = db.relationship('GuidedJournalResponse', order_by='GuidedJournalResponse.id', back_populates='journal_entry')

class GuidedJournalResponse(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    journal_entry_id = db.Column(db.Integer, db.ForeignKey('journal_entry.id'), nullable=False)
    question = db.Column(db.String(250), nullable=False)
    response = db.Column(db.Text, nullable=False)

    journal_entry = db.relationship('JournalEntry', back_populates='guided_responses')



@app.route('/')
def index():
    return render_template('index.html')

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/guided_entry', methods=['GET', 'POST'])
@login_required
def guided_entry():
    if request.method == 'POST':
        new_entry = JournalEntry(user_id=current_user.id, content="Guided Journal Entry")
        db.session.add(new_entry)
        db.session.flush()  # This allows us to use new_entry.id immediately

        # Example of handling the "feeling" response
        feeling_response = GuidedJournalResponse(
            journal_entry_id=new_entry.id,
            question="How are you feeling on a scale of 1-10?",
            response=request.form['feeling']
        )
        db.session.add(feeling_response)

        # Repeat for each guided question:
        # Create a GuidedJournalResponse object with the question and the user's response
        # For example, for the "feeling_reason" question:
        feeling_reason_response = GuidedJournalResponse(
            journal_entry_id=new_entry.id,
            question="Why do you feel that way?",
            response=request.form['feeling_reason']
        )
        db.session.add(feeling_reason_response)

        # ... Add more questions as needed ...

        db.session.commit()
        return redirect(url_for('view_entries'))

    # Logic to determine which questions to show (your conditions)
    show_time_elapsed_question = False
    last_entry = JournalEntry.query.filter_by(user_id=current_user.id).order_by(JournalEntry.timestamp.desc()).first()

    if last_entry and (datetime.now() - last_entry.timestamp).total_seconds() > 8 * 3600:
        show_time_elapsed_question = True

    return render_template('guided_entry.html', show_time_elapsed_question=show_time_elapsed_question)



@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Logic to handle registration form
        hashed_password = generate_password_hash(request.form['password'])
        new_user = User(username=request.form['username'], password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/add_entry', methods=['GET', 'POST'])
@login_required
def add_entry():
    if request.method == 'POST':
        new_entry = JournalEntry(content=request.form['content'], user_id=current_user.id)
        db.session.add(new_entry)
        db.session.commit()
        return redirect(url_for('view_entries'))
    return render_template('add_entry.html')

@app.route('/view_entries')
@login_required
def view_entries():
    entries = JournalEntry.query.filter_by(user_id=current_user.id).order_by(JournalEntry.timestamp.desc()).all()
    local_timezone = pytz.timezone("America/Los_Angeles")  # Replace with your time zone

    for entry in entries:
        entry.local_timestamp = local_timezone.fromutc(entry.timestamp)
        entry.guided_responses_list = GuidedJournalResponse.query.filter_by(journal_entry_id=entry.id).all()

    return render_template('view_entries.html', entries=entries)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('view_entries'))
        else:
            return 'Invalid username or password'

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/delete_entry/<int:entry_id>', methods=['POST'])
@login_required
def delete_entry(entry_id):
    entry_to_delete = JournalEntry.query.get_or_404(entry_id)
    if entry_to_delete.user_id != current_user.id:
        # Prevent deletion if the current user is not the owner of the entry
        return redirect(url_for('view_entries'))

    # Delete all GuidedJournalResponse records associated with this entry
    GuidedJournalResponse.query.filter_by(journal_entry_id=entry_id).delete()

    # Now delete the JournalEntry
    db.session.delete(entry_to_delete)
    db.session.commit()
    return redirect(url_for('view_entries'))




if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # This will now execute within the app context
    app.run(debug=True)
