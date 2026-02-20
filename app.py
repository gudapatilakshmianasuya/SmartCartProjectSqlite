from flask import Flask, render_template, request, flash, session, redirect
import sqlite3   # ✅ changed from mysql.connector
import config
from flask_mail import Mail, Message
from flask import make_response, render_template
from pdf_generator import generate_pdf
import random
import bcrypt
import os
from werkzeug.utils import secure_filename
import razorpay

app = Flask(__name__)

# Secret key for session management
app.secret_key = config.SECRET_KEY

razorpay_client = razorpay.Client(
    auth=(config.RAZORPAY_KEY_ID, config.RAZORPAY_KEY_SECRET)
)

mail = Mail(app)

def send_email(to, subject, body):
    msg = Message(
        subject=subject,
        sender=app.config['MAIL_USERNAME'],
        recipients=[to]
    )
    msg.body = body
    mail.send(msg)

# -----------------------------------------------------------------------------------------------------
# EMAIL CONFIGURATION
app.config['MAIL_SERVER'] = config.MAIL_SERVER
app.config['MAIL_PORT'] = config.MAIL_PORT
app.config['MAIL_USE_TLS'] = config.MAIL_USE_TLS
app.config['MAIL_USERNAME'] = config.MAIL_USERNAME
app.config['MAIL_PASSWORD'] = config.MAIL_PASSWORD
mail = Mail(app)

# -------------------------------------------------------------------------------------------------
# SQLITE DATABASE CONNECTION SETUP
def get_db_connection():
    conn = sqlite3.connect('smartcart.db')
    conn.row_factory = sqlite3.Row
    return conn

# ================================================================================================
@app.route('/about')
def about():
    return render_template("about.html")

@app.route('/contact')
def Contact():
    return render_template("contact.html")

#---------------------------------------------------------------------------------------------

#-----------------------------------------------------------------------------------------
#ROUTE1  ADMIN SIGNUP PAGE
@app.route('/admin-signup',methods=['GET','POST'])
def admin_signup():
    #shoe form
    if request.method=="GET":
        return render_template("admin/admin_signup.html")
    
    #POST-->Process signup
    name=request.form['name']
    email=request.form['email']

    #check if admin email already exists
    conn=get_db_connection()
    cursor=conn.cursor()
    cursor.execute("select admin_id from admin where email=?",(email,))
    existing_admin=cursor.fetchone()
    cursor.close()
    conn.close()

    if existing_admin:
        flash("This email is already registered.please login instead.","danger")
        return render_template('/admin-signup')
    
    #2 save user input temporarily in session
    session['signup_name']=name
    session['signup_email']=email 

    #3  generate Otp and store in session
    otp=random.randint(100000,999999)
    session['otp']=otp

    #4 send otp email
    message=Message(
    subject="SmartCard Admin OTP",
    sender=config.MAIL_USERNAME,
    recipients=[email]
    )
    message.body = f"Your OTP for SmartCart Admin Registration is: {otp}"
    mail.send(message)

    flash("OTP sent to your email!", "success")
    return redirect('/verify-otp')


# ROUTE 2: DISPLAY OTP PAGE
# ---------------------------------------------------------
@app.route('/verify-otp', methods=['GET'])
def verify_otp_get():
    return render_template("admin/verify_otp.html")
# ROUTE 3: VERIFY OTP + SAVE ADMIN
# ---------------------------------------------------------
@app.route('/verify-otp', methods=['POST'])
def verify_otp_post():
    
    # User submitted OTP + Password
    user_otp = request.form['otp']
    password = request.form['password']

    # Compare OTP
    if str(session.get('otp')) != str(user_otp):
        flash("Invalid OTP. Try again!", "danger")
        return redirect('/verify-otp')

    # Hash password using bcrypt
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # Insert admin into database
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO admin (name, email, password) VALUES (?, ?, ?)",
        (session['signup_name'], session['signup_email'], hashed_password)
    )
    conn.commit()
    cursor.close()
    conn.close()

    # Clear temporary session data
    session.pop('otp', None)
    session.pop('signup_name', None)
    session.pop('signup_email', None)

    flash("Admin Registered Successfully!", "success")
    return redirect('/admin-login')
#===============================================================================================================
# ===============================
# ADMIN FORGOT PASSWORD
# ===============================
@app.route('/admin/forgot-password', methods=['GET', 'POST'])
def admin_forgot_password():

    if request.method == 'POST':
        email = request.form['email']

        # Check if admin exists
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM admin WHERE email = ?", (email,))
        admin = cursor.fetchone()

        if admin:
            otp = random.randint(100000, 999999)

            session['admin_otp'] = otp
            session['admin_email'] = email

            # ✅ Correct email sending
            subject = "Admin Password Reset OTP"
            body = f"Hello Admin,\n\nYour OTP for password reset is: {otp}\n\nDo not share this OTP."

            send_email(email, subject, body)

            flash("OTP sent to your email", "success")
            return redirect('/admin/reset-password')
        else:
            flash("Admin email not found", "danger")

        cursor.close()
        conn.close()

    return render_template('admin/forgot_password.html')


# ===============================
# ADMIN RESET PASSWORD
# ===============================
@app.route('/admin/reset-password', methods=['GET', 'POST'])
def admin_reset_password():

    if request.method == 'POST':
        entered_otp = request.form['otp']
        new_password = request.form['password']

        # Check OTP
        if str(session.get('admin_otp')) == entered_otp:

            # 🔐 Hash the new password
            hashed_password = bcrypt.hashpw(
                new_password.encode('utf-8'),
                bcrypt.gensalt()
            )

            conn = get_db_connection()
            cursor = conn.cursor()

            cursor.execute(
                "UPDATE admin SET password=? WHERE email=?",
                (hashed_password, session.get('admin_email'))
            )
            conn.commit()
            cursor.close()
            conn.close()

            # Clear session
            session.pop('admin_otp', None)
            session.pop('admin_email', None)

            flash("Password reset successful", "success")
            return redirect('/admin-login')

        else:
            flash("Invalid OTP", "danger")

    return render_template('admin/reset_password.html')


#ROUTE 4   
#=================================================================================================================
@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():

    # Show login page
    if request.method == 'GET':
        return render_template("admin/admin_login.html")

    # POST → Validate login
    email = request.form['email']
    password = request.form['password']

    # Step 1: Check if admin email exists
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM admin WHERE email=?", (email,))
    admin = cursor.fetchone()

    cursor.close()
    conn.close()

    if admin is None:
        flash("Email not found! Please register first.", "danger")
        return redirect('/admin-login')

    # Step 2: Compare entered password with hashed password
    stored_hashed_password = admin['password']

    if not bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password):
        flash("Incorrect password! Try again.", "danger")
        return redirect('/admin-login')

    # Step 5: If login success → Create admin session
    session['admin_id'] = admin['admin_id']
    session['admin_name'] = admin['name']
    session['admin_email'] = admin['email']

    flash("Login Successful!", "success")
    return redirect('/admin-dashboard')



# =================================================================
# ROUTE 5: ADMIN DASHBOARD (PROTECTED ROUTE)
# =================================================================
@app.route('/admin-dashboard')
def admin_dashboard():

    # Protect dashboard → Only logged-in admin can access
    if 'admin_id' not in session:
        flash("Please login to access dashboard!", "danger")
        return redirect('/admin-login')

    # Send admin name to dashboard UI
    return render_template("admin/dashboard.html", admin_name=session['admin_name'])
# =================================================================
# ROUTE 6: ADMIN LOGOUT
# =================================================================
@app.route('/admin-logout')
def admin_logout():

    # Clear admin session
    session.pop('admin_id', None)
    session.pop('admin_name', None)
    session.pop('admin_email', None)

    flash("Logged out successfully.", "success")
    return redirect('/admin-login')

UPLOAD_FOLDER = 'static/uploads/product_images'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


# =================================================================
# ROUTE 7: SHOW ADD PRODUCT PAGE (Protected Route)
# =================================================================
@app.route('/admin/add-item', methods=['GET'])
def add_item_page():

    # Only logged-in admin can access
    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    return render_template("admin/add_item.html")



# =================================================================
# ROUTE 8: ADD PRODUCT INTO DATABASE
# =================================================================
@app.route('/admin/add-item', methods=['POST'])
def add_item():

    # 🔐 Check admin session
    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    # 1️⃣ Get form data
    name = request.form['name']
    description = request.form['description']
    category = request.form['category']
    price = request.form['price']
    image_file = request.files['image']

    # 2️⃣ Validate image upload
    if not image_file or image_file.filename == "":
        flash("Please upload a product image!", "danger")
        return redirect('/admin/add-item')

    # 3️⃣ Secure filename
    filename = secure_filename(image_file.filename)

    # 4️⃣ Save image
    image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    image_file.save(image_path)

    try:
        # 5️⃣ Insert product with admin_id
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO products 
            (name, description, category, price, image, admin_id) 
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (name, description, category, price, filename, session['admin_id'])
        )

        conn.commit()
        cursor.close()
        conn.close()

        flash("Product added successfully!", "success")

    except Exception as e:
        flash("Error adding product!", "danger")
        print("Error:", e)

    return redirect('/admin/add-item')


# =================================================================
# ROUTE 9: DISPLAY ALL PRODUCTS (Admin)
# =================================================================
@app.route('/admin/item-list')
def item_list():

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']
    search = request.args.get('search', '')
    category_filter = request.args.get('category', '')

    conn = get_db_connection()
    cursor = conn.cursor()

    # 1️⃣ Fetch category list only for this admin
    cursor.execute(
        "SELECT DISTINCT category FROM products WHERE admin_id = ?",
        (admin_id,)
    )
    categories = cursor.fetchall()

    # 2️⃣ Build query (Filter by admin_id first)
    query = "SELECT * FROM products WHERE admin_id = ?"
    params = [admin_id]

    if search:
        query += " AND name LIKE ?"
        params.append("%" + search + "%")

    if category_filter:
        query += " AND category = ?"
        params.append(category_filter)

    cursor.execute(query, params)
    products = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        "admin/item_list.html",
        products=products,
        categories=categories
    )



#=================================================================
# ROUTE 10: VIEW SINGLE PRODUCT DETAILS
# =================================================================
@app.route('/admin/view-item/<int:item_id>')
def view_item(item_id):

    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM products WHERE product_id = ? AND admin_id = ?",
        (item_id, admin_id)
    )
    product = cursor.fetchone()

    cursor.close()
    conn.close()

    if not product:
        flash("Product not found or access denied!", "danger")
        return redirect('/admin/item-list')

    return render_template("admin/view_item.html", product=product)


# =================================================================
# ROUTE 11: SHOW UPDATE FORM WITH EXISTING DATA
# =================================================================
@app.route('/admin/update-item/<int:item_id>', methods=['GET'])
def update_item_page(item_id):

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM products WHERE product_id = ? AND admin_id = ?",
        (item_id, admin_id)
    )
    product = cursor.fetchone()

    cursor.close()
    conn.close()

    if not product:
        flash("Product not found or access denied!", "danger")
        return redirect('/admin/item-list')

    return render_template("admin/update_item.html", product=product)


# =================================================================
# ROUTE 12: UPDATE PRODUCT + OPTIONAL IMAGE REPLACE
# =================================================================
@app.route('/admin/update-item/<int:item_id>', methods=['POST'])
def update_item(item_id):

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    name = request.form['name']
    description = request.form['description']
    category = request.form['category']
    price = request.form['price']
    new_image = request.files['image']

    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch only if belongs to this admin
    cursor.execute(
        "SELECT * FROM products WHERE product_id = ? AND admin_id = ?",
        (item_id, admin_id)
    )
    product = cursor.fetchone()

    if not product:
        flash("Product not found or access denied!", "danger")
        return redirect('/admin/item-list')

    old_image_name = product['image']

    if new_image and new_image.filename != "":
        from werkzeug.utils import secure_filename
        new_filename = secure_filename(new_image.filename)

        new_image_path = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
        new_image.save(new_image_path)

        old_image_path = os.path.join(app.config['UPLOAD_FOLDER'], old_image_name)
        if os.path.exists(old_image_path):
            os.remove(old_image_path)

        final_image_name = new_filename
    else:
        final_image_name = old_image_name

    cursor.execute("""
        UPDATE products
        SET name=?, description=?, category=?, price=?, image=?
        WHERE product_id=? AND admin_id=?
    """, (name, description, category, price, final_image_name, item_id, admin_id))

    conn.commit()
    cursor.close()
    conn.close()

    flash("Product updated successfully!", "success")
    return redirect('/admin/item-list')


#⭐ ROUTE 13: Delete Product + Delete Image from Server
# =================================================================
# DELETE PRODUCT (DELETE DB ROW + DELETE IMAGE FILE)
# =================================================================
@app.route('/admin/delete-item/<int:item_id>')
def delete_item(item_id):

    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "UPDATE products SET status='Inactive' WHERE product_id=? AND admin_id=?",
        (item_id, admin_id)
    )

    conn.commit()
    cursor.close()
    conn.close()

    flash("Product marked as Inactive.", "success")
    return redirect('/admin/item-list')

# =================================================================
# ROUTE 14: SHOW ADMIN PROFILE DATA
# =================================================================
@app.route('/admin/profile', methods=['GET'])
def admin_profile():

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM admin WHERE admin_id = ?", (admin_id,))
    admin = cursor.fetchone()

    cursor.close()
    conn.close()

    return render_template("admin/admin_profile.html", admin=admin)

# =================================================================
# ROUTE 15: UPDATE ADMIN PROFILE (NAME, EMAIL, PASSWORD, IMAGE)
# =================================================================
@app.route('/admin/profile', methods=['POST'])
def admin_profile_update():

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    # 1️⃣ Get form data
    name = request.form['name']
    email = request.form['email']
    new_password = request.form['password']
    new_image = request.files['profile_image']

    conn = get_db_connection()
    cursor = conn.cursor()

    # 2️⃣ Fetch old admin data
    cursor.execute("SELECT * FROM admin WHERE admin_id = ?", (admin_id,))
    admin = cursor.fetchone()

    old_image_name = admin['profile_image']

    # 3️⃣ Update password only if entered
    if new_password:
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
    else:
        hashed_password = admin['password']  # keep old password

    # 4️⃣ Process new profile image if uploaded
    if new_image and new_image.filename != "":
        
        from werkzeug.utils import secure_filename
        new_filename = secure_filename(new_image.filename)

        # Save new image
        image_path = os.path.join(app.config['ADMIN_UPLOAD_FOLDER'], new_filename)
        new_image.save(image_path)

        # Delete old image
        if old_image_name:
            old_image_path = os.path.join(app.config['ADMIN_UPLOAD_FOLDER'], old_image_name)
            if os.path.exists(old_image_path):
                os.remove(old_image_path)

        final_image_name = new_filename
    else:
        final_image_name = old_image_name

    # 5️⃣ Update database
    cursor.execute("""
        UPDATE admin
        SET name=?, email=?, password=?, profile_image=?
        WHERE admin_id=?
    """, (name, email, hashed_password, final_image_name, admin_id))

    conn.commit()
    cursor.close()
    conn.close()

    # Update session name for UI consistency
    session['admin_name'] = name  
    session['admin_email'] = email

    flash("Profile updated successfully!", "success")
    return redirect('/admin/profile')



#=====================================================================================================

@app.route('/admin/restore-item/<int:item_id>')
def restore_item(item_id):

    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "UPDATE products SET status='Active' WHERE product_id=? AND admin_id=?",
        (item_id, admin_id)
    )

    conn.commit()
    cursor.close()
    conn.close()

    flash("Product restored successfully!", "success")
    return redirect('/admin/item-list')



#===================================================================================================================

#________________________________________USER MODULE_________________________________________________________





#⭐ ROUTE 1: User Registration (GET + POST)
# =================================================================
# ROUTE 16: USER REGISTRATION
# =================================================================

@app.route('/user-register', methods=['GET', 'POST'])
def user_register():

    if request.method == "GET":
        return render_template("user/user_register.html")

    name = request.form['name']
    email = request.form['email']
    
    # Check if email exists
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT user_id FROM users WHERE email=?", (email,))
    existing_user = cursor.fetchone()
    cursor.close()
    conn.close()

    if existing_user:
        flash("Email already registered. Please login.", "danger")
        return redirect('/user-register')

    # Store data temporarily in session
    session['user_signup_name'] = name
    session['user_signup_email'] = email
    
    # Generate OTP
    otp = random.randint(100000, 999999)
    session['user_otp'] = otp

    # Send OTP Email
    message = Message(
        subject="SmartCart User Registration OTP",
        sender=config.MAIL_USERNAME,
        recipients=[email]
    )
    message.body = f"Your OTP for SmartCart registration is: {otp}"
    mail.send(message)

    flash("OTP sent to your email!", "success")
    return redirect('/user/verify-otp')

#⭐ ROUTE 3:  verify otp(GET + POST)
# =================================================================
# ROUTE: 17 verify otp
# =================================================================
@app.route('/user/verify-otp', methods=['GET'])
def user_verify_otp_page():
    return render_template("user/verify_otp.html")




# ==========================================================
# ROUTE: VERIFY OTP + SAVE USER
# ==========================================================
@app.route('/user/verify-otp', methods=['POST'])
def user_verify_otp_post():
    
    # User submitted OTP + Password
    user_otp = request.form['otp']
    password = request.form['password']

    # Compare OTP
    if str(session.get('user_otp')) != str(user_otp):
        flash("Invalid OTP. Try again!", "danger")
        return redirect('/user/verify-otp')

    # Hash password using bcrypt
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # Insert user into database
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
        (session['user_signup_name'], session['user_signup_email'], hashed_password)
    )
    conn.commit()
    cursor.close()
    conn.close()

    # Clear temporary session data
    session.pop('user_otp', None)
    session.pop('user_signup_name', None)
    session.pop('user_signup_email', None)

    flash("User Registered Successfully!", "success")
    return redirect('/user/user-login')




#⭐ ROUTE 2: User Login (GET + POST)
# =================================================================
# ROUTE: 17 USER LOGIN
# =================================================================
@app.route('/user/user-login', methods=['GET', 'POST'])
def user_login():

    # Show login page
    if request.method == 'GET':
        return render_template("user/user_login.html")

    # POST → Validate login
    email = request.form['email']
    password = request.form['password']

    # Step 1: Check if user email exists
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE email=?", (email,))
    user = cursor.fetchone()

    cursor.close()
    conn.close()

    if user is None:
        flash("Email not found! Please register first.", "danger")
        return redirect('/user/user-login')

    # Step 2: Compare entered password with hashed password
    stored_hashed_password = user['password']

    if not bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password):
        flash("Incorrect password! Try again.", "danger")
        return redirect('/user/user-login')

    # Step 3: If login success → Create user session
    session['user_id'] = user['user_id']
    session['user_name'] = user['name']
    session['user_email'] = user['email']

    flash("Login Successful!", "success")
    return redirect('/user/user-dashboard')   # redirect to homepage


#=======================================================================================================
#+++++++++++++++++++++++++++++++++++++++++++++forgetpassword route_____________________________________________

@app.route('/user/forgot-password', methods=['GET', 'POST'])
def user_forgot_password():

    if request.method == 'POST':
        email = request.form['email']

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM users WHERE email=?", (email,))
        user = cursor.fetchone()

        cursor.close()
        conn.close()

        if not user:
            flash("Email not found!", "danger")
            return redirect('/user/forgot-password')

        # Generate OTP
        otp = random.randint(100000, 999999)
        session['reset_otp'] = otp
        session['reset_email'] = email

        # Send email (use your existing mail function)
        send_email(email, "Password Reset OTP", f"Your OTP is {otp}")

        flash("OTP sent to your email.", "success")
        return redirect('/user/reset-password')

    return render_template("user/forgot_password.html")


#===========================user reset password++++++++++++++++++++++++++++++++++++++++++++++++++++++
@app.route('/user/reset-password', methods=['GET', 'POST'])
def user_reset_password():

    if request.method == 'POST':
        entered_otp = request.form['otp']
        new_password = request.form['password']

        if str(session.get('reset_otp')) != entered_otp:
            flash("Invalid OTP!", "danger")
            return redirect('/user/reset-password')

        hashed_password = bcrypt.hashpw(
            new_password.encode('utf-8'),
            bcrypt.gensalt()
        )

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            "UPDATE users SET password=? WHERE email=?",
            (hashed_password, session['reset_email'])
        )

        conn.commit()
        cursor.close()
        conn.close()

        session.pop('reset_otp', None)
        session.pop('reset_email', None)

        flash("Password reset successful! Please login.", "success")
        return redirect('/user/user-login')

    return render_template("user/reset_password.html")




#⭐ ROUTE 3: User Dashboard (Protected)
# =================================================================
# ROUTE 18: USER DASHBOARD
# =================================================================
@app.route('/user/user-dashboard')
def user_dashboard():

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user/user-login')

    return render_template("user/user_home.html", user_name=session['user_name'])



#⭐ ROUTE 4: User Logout
# =================================================================
# ROUTE 19: USER LOGOUT
# =================================================================
#@app.route('/user-logout')
#def user_logout():
    
#    session.pop('user_id', None)
#    session.pop('user_name', None)
#    session.pop('user_email', None)
#    flash("Logged out successfully!", "success")
#    return redirect('/user/user-login')

@app.route('/user-logout')
def user_logout():
    
    session.pop('user_id', None)
    session.pop('user_name', None)
    session.pop('user_email', None)
    session.pop('cart', None)   
    session.pop('razorpay_order_id', None)

    flash("Logged out successfully.", "success")
    return redirect('/user/user-login')


#=================================================================
# ROUTE 20: USER PRODUCT LISTING (SEARCH + FILTER)
# =================================================================
@app.route('/user/products')
def user_products():

    if 'user_id' not in session:
        flash("Please login to view products!", "danger")
        return redirect('/user/user-login')

    search = request.args.get('search', '')
    category_filter = request.args.get('category', '')

    conn = get_db_connection()
    cursor = conn.cursor()

    # Only show active categories
    cursor.execute("SELECT DISTINCT category FROM products WHERE status='Active'")
    categories = cursor.fetchall()

    # Base query
    query = "SELECT * FROM products WHERE status='Active'"
    params = []

    if search:
        query += " AND name LIKE ?"
        params.append("%" + search + "%")

    if category_filter:
        query += " AND category = ?"
        params.append(category_filter)

    cursor.execute(query, params)
    products = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        "user/user_products.html",
        products=products,
        categories=categories
    )

# =================================================================
# ROUTE 21: USER PRODUCT DETAILS PAGE
# =================================================================
@app.route('/user/product/<int:product_id>')
def user_product_details(product_id):

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user/user-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM products WHERE product_id = ? AND status='Active'",
        (product_id,)
    )

    product = cursor.fetchone()

    cursor.close()
    conn.close()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/user/products')

    return render_template("user/product_details.html", product=product)





# =================================================================
# ADD ITEM TO CART
# =================================================================
# If exists → increase quantity
@app.route('/user/add-to-cart/<int:product_id>')
def add_to_cart(product_id):

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user/user-login')

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    # Check if product already in cart
    cursor.execute("""
        SELECT * FROM cart 
        WHERE user_id=? AND product_id=?
    """, (user_id, product_id))

    existing = cursor.fetchone()

    if existing:
        cursor.execute("""
            UPDATE cart 
            SET quantity = quantity + 1
            WHERE user_id=? AND product_id=?
        """, (user_id, product_id))
    else:
        cursor.execute("""
            INSERT INTO cart (user_id, product_id, quantity)
            VALUES (?, ?, 1)
        """, (user_id, product_id))

    conn.commit()
    cursor.close()
    conn.close()

    flash("Item added to cart!", "success")
    return redirect(request.referrer)


#⭐ ROUTE 2: View Cart Page
# =================================================================
# VIEW CART PAGE
# =================================================================
@app.route('/user/cart')
def view_cart():

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user/user-login')

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT c.*, p.name, p.price, p.image
        FROM cart c
        JOIN products p ON c.product_id = p.product_id
        WHERE c.user_id = ?
    """, (user_id,))

    cart_items = cursor.fetchall()

    grand_total = sum(item['price'] * item['quantity'] for item in cart_items)

    cursor.close()
    conn.close()

    return render_template("user/cart.html", cart=cart_items, grand_total=grand_total)


# INCREASE QUANTITY
# =================================================================
@app.route('/user/cart/increase/<int:pid>')
def increase_quantity(pid):

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user/user-login')

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE cart 
        SET quantity = quantity + 1
        WHERE user_id = ? AND product_id = ?
    """, (user_id, pid))

    conn.commit()
    cursor.close()
    conn.close()

    return redirect('/user/cart')
#⭐ ROUTE 4: Decrease Quantity
# =================================================================
# DECREASE QUANTITY
# =================================================================
@app.route('/user/cart/decrease/<int:pid>')
def decrease_quantity(pid):

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user/user-login')

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT quantity FROM cart 
        WHERE user_id = ? AND product_id = ?
    """, (user_id, pid))

    item = cursor.fetchone()

    if item:
        if item['quantity'] > 1:
            cursor.execute("""
                UPDATE cart 
                SET quantity = quantity - 1
                WHERE user_id = ? AND product_id = ?
            """, (user_id, pid))
        else:
            cursor.execute("""
                DELETE FROM cart 
                WHERE user_id = ? AND product_id = ?
            """, (user_id, pid))

    conn.commit()
    cursor.close()
    conn.close()

    return redirect('/user/cart')


#⭐ ROUTE 5: Remove Item Completely
# =================================================================
# REMOVE ITEM
# =================================================================
@app.route('/user/cart/remove/<int:pid>')
def remove_from_cart(pid):

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user/user-login')

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        DELETE FROM cart 
        WHERE user_id = ? AND product_id = ?
    """, (user_id, pid))

    conn.commit()
    cursor.close()
    conn.close()

    flash("Item removed!", "success")
    return redirect('/user/cart')
# =================================================================
# ROUTE: CREATE RAZORPAY ORDER
# =================================================================
# =================================================================
# ROUTE: CREATE RAZORPAY ORDER + STORE ADDRESS IN SESSION
# =================================================================
@app.route('/user/pay', methods=['GET', 'POST'])
def user_pay():

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user/user-login')

    user_id = session['user_id']

    # 🔥 GET address_id from URL
    address_id = request.args.get('address_id')

    if not address_id:
        flash("Please select delivery address!", "danger")
        return redirect('/user/address')

    # Save selected address in session
    session['selected_address_id'] = address_id

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT c.*, p.name, p.price
        FROM cart c
        JOIN products p ON c.product_id = p.product_id
        WHERE c.user_id = ?
    """, (user_id,))

    cart_items = cursor.fetchall()

    if not cart_items:
        flash("Your cart is empty!", "danger")
        return redirect('/user/products')

    total_amount = sum(item['price'] * item['quantity'] for item in cart_items)

    razorpay_amount = int(total_amount * 100)

    razorpay_order = razorpay_client.order.create({
        "amount": razorpay_amount,
        "currency": "INR",
        "payment_capture": "1"
    })

    session['razorpay_order_id'] = razorpay_order['id']

    cursor.close()
    conn.close()

    return render_template(
        "user/payment.html",
        amount=total_amount,
        key_id=config.RAZORPAY_KEY_ID,
        order_id=razorpay_order['id']
    )



# =====================================================
# ADDRESS PAGE (Before Payment)
# =====================================================
@app.route('/user/address', methods=['GET', 'POST'])
def user_address():

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user/user-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    # Save new address
    if request.method == 'POST':

        full_name = request.form.get('full_name')
        phone = request.form.get('phone')
        address_line = request.form.get('address_line')
        city = request.form.get('city')
        state = request.form.get('state')
        pincode = request.form.get('pincode')

        # ✅ Validation to prevent crash
        if not all([full_name, phone, address_line, city, state, pincode]):
            flash("Please fill all fields!", "danger")
            return redirect('/user/address')

        cursor.execute("""
            INSERT INTO user_addresses 
            (user_id, full_name, phone, address_line, city, state, pincode)
            VALUES (?,?,?,?,?,?,?)
        """, (
            session['user_id'],
            full_name,
            phone,
            address_line,
            city,
            state,
            pincode
        ))

        conn.commit()
        flash("Address added successfully!", "success")

    # Fetch existing addresses
    cursor.execute("""
        SELECT * FROM user_addresses 
        WHERE user_id=? ORDER BY created_at DESC
    """, (session['user_id'],))

    addresses = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template("user/address.html", addresses=addresses)


# TEMP SUCCESS PAGE (Verification in Day 13)
# =================================================================
@app.route('/payment-success')
def payment_success():

    payment_id = request.args.get('payment_id')
    order_id = request.args.get('order_id')

    if not payment_id:
        flash("Payment failed!", "danger")
        return redirect('/user/cart')

    return render_template(
        "user/payment_success.html",
        payment_id=payment_id,
        order_id=order_id
    )
# ------------------------------
# Route: Verify Payment and Store Order
# ------------------------------
# ------------------------------
# Route: Verify Payment and Store Order (WITH ADDRESS FIX)
# ------------------------------
@app.route('/verify-payment', methods=['POST'])
def verify_payment():

    if 'user_id' not in session:
        flash("Please login to complete the payment.", "danger")
        return redirect('/user/user-login')

    razorpay_payment_id = request.form.get('razorpay_payment_id')
    razorpay_order_id = request.form.get('razorpay_order_id')
    razorpay_signature = request.form.get('razorpay_signature')

    if not (razorpay_payment_id and razorpay_order_id and razorpay_signature):
        flash("Payment verification failed (missing data).", "danger")
        return redirect('/user/cart')

    payload = {
        'razorpay_order_id': razorpay_order_id,
        'razorpay_payment_id': razorpay_payment_id,
        'razorpay_signature': razorpay_signature
    }

    try:
        razorpay_client.utility.verify_payment_signature(payload)
    except Exception:
        flash("Payment verification failed. Please try again.", "danger")
        return redirect('/user/cart')

    user_id = session['user_id']

    # ✅ GET SELECTED ADDRESS
    address_id = session.get('selected_address_id')

    if not address_id:
        flash("Address not selected.", "danger")
        return redirect('/user/cart')

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Fetch cart
        cursor.execute("""
            SELECT c.*, p.name, p.price
            FROM cart c
            JOIN products p ON c.product_id = p.product_id
            WHERE c.user_id = ?
        """, (user_id,))
        cart_items = cursor.fetchall()

        if not cart_items:
            flash("Cart is empty. Cannot create order.", "danger")
            return redirect('/user/products')

        # Calculate total
        total_amount = sum(item['price'] * item['quantity'] for item in cart_items)

        # Get per-user order number
        cursor.execute("""
            SELECT COUNT(*) AS total_orders
            FROM orders
            WHERE user_id = ?
        """, (user_id,))
        result = cursor.fetchone()
        user_order_no = result['total_orders'] + 1

        # Insert into orders
        cursor.execute("""
            INSERT INTO orders 
            (user_id, user_order_no, address_id,
             razorpay_order_id, razorpay_payment_id,
             amount, payment_status)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            user_id,
            user_order_no,
            address_id,
            razorpay_order_id,
            razorpay_payment_id,
            total_amount,
            'Paid'
        ))

        order_db_id = cursor.lastrowid

        # Insert order items
        for item in cart_items:
            cursor.execute("""
                INSERT INTO order_items
                (order_id, product_id, product_name, quantity, price)
                VALUES (?, ?, ?, ?, ?)
            """, (
                order_db_id,
                item['product_id'],
                item['name'],
                item['quantity'],
                item['price']
            ))
        # Clear cart
        cursor.execute("DELETE FROM cart WHERE user_id = ?", (user_id,))
        # Clear selected address from session
        session.pop('selected_address_id', None)
        conn.commit()
        flash("Payment successful and order placed!", "success")
        return redirect(f"/user/order-success/{order_db_id}")
    except Exception:
        conn.rollback()
        flash("There was an error saving your order.", "danger")
        return redirect('/user/cart')
    finally:
        cursor.close()
        conn.close()
#==============================================================================================================
#✅ Route: Order Success Page
#Create a page to show order confirmation and order id:
@app.route('/user/order-success/<int:order_db_id>')
def order_success(order_db_id):

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user/user-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM orders WHERE order_id=? AND user_id=?",
        (order_db_id, session['user_id'])
    )
    order = cursor.fetchone()

    if not order:
        flash("Order not found.", "danger")
        return redirect('/user/products')

    cursor.execute("""
        SELECT oi.*, p.name AS product_name
        FROM order_items oi
        JOIN products p ON oi.product_id = p.product_id
        WHERE oi.order_id = ?
    """, (order_db_id,))

    items = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template("user/order_success.html", order=order, items=items)
#=====================================================================================================================
@app.route('/user/my-orders')
def my_orders():
    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user/user-login')
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM orders WHERE user_id=? ORDER BY created_at DESC",
        (session['user_id'],)
    )
    orders = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template("user/my_orders.html", orders=orders)
# ----------------------------
# GENERATE INVOICE PDF
# ----------------------------
@app.route("/user/download-invoice/<int:order_id>")
def download_invoice(order_id):

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user/user-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    # 1️⃣ Fetch order
    cursor.execute("""
        SELECT * FROM orders 
        WHERE order_id=? AND user_id=?
    """, (order_id, session['user_id']))
    order = cursor.fetchone()

    if not order:
        flash("Order not found.", "danger")
        return redirect('/user/my-orders')

    # 2️⃣ Fetch order items
    cursor.execute("""
        SELECT * FROM order_items 
        WHERE order_id=?
    """, (order_id,))
    items = cursor.fetchall()

    # 3️⃣ Fetch user details
    cursor.execute("""
        SELECT name, email 
        FROM users 
        WHERE user_id=?
    """, (session['user_id'],))
    user = cursor.fetchone()

    cursor.close()
    conn.close()

    # 4️⃣ Pass user to template
    html = render_template(
        "user/invoice.html",
        order=order,
        items=items,
        user=user
    )

    pdf = generate_pdf(html)

    if not pdf:
        flash("Error generating PDF", "danger")
        return redirect('/user/my-orders')

    response = make_response(pdf.getvalue())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f"attachment; filename=invoice_{order_id}.pdf"

    return response

#--------------------------------------------------------------------------------------------------
#Run the application
if __name__ == '__main__':
    app.run(debug=True)