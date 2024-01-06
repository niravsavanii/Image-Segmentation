import mimetypes
import os
import random
from tkinter import Image
import numpy as np
import matplotlib
import torch
import os
from urllib.request import urlretrieve

matplotlib.use('Agg')
import matplotlib.pyplot as plt
from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_mail import *
import mysql.connector
import hashlib
import re
import cv2
from PIL import Image
from werkzeug.utils import secure_filename

if getattr(sys, 'frozen', False):
    template_folder = os.path.join(sys._MEIPASS, 'templates')
    static_folder = os.path.join(sys._MEIPASS, 'static')
    checkpoint_dir = os.path.dirname(sys.executable)
    app = Flask(__name__, template_folder=template_folder, static_folder=static_folder)
    app.debug = True
else:
    checkpoint_dir = os.path.dirname(os.path.abspath(__file__))
    app = Flask(__name__)

# Import necessary SAM modules
sys.path.append("..")
from segment_anything import sam_model_registry, SamAutomaticMaskGenerator

# Get the absolute path to the checkpoint file
checkpoint_rel_path = os.path.join('static', 'sam_vit_h_4b8939.pth')
sam_checkpoint = os.path.join(checkpoint_dir, checkpoint_rel_path)

# Load the SAM model
model_type = "vit_h"
device = "cuda" if torch.cuda.is_available() else "cpu"

sam = sam_model_registry[model_type](checkpoint=sam_checkpoint)
sam.to(device=device)

# Configure upload folder
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

app.secret_key = 'xyz23pqr4'
con = mysql.connector.connect(host='localhost', user='root', password='Nir@v72038',
                              database='textile_design_segmentation')
cursor = con.cursor()

# mail configuration
app.config["MAIL_SERVER"] = 'smtp.office365.com'
app.config["MAIL_PORT"] = '587'
app.config["MAIL_USERNAME"] = 'imagesegmentation@outlook.com'
app.config["MAIL_PASSWORD"] = 'Demo@123'
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USE_SSL"] = False
mail = Mail(app)


def validateRegistrationForm(data):
    errors = []

    firstName = data.get('firstName')
    if not firstName:
        errors.append('First name is required.')
    elif not firstName.isalpha():
        errors.append('First name must contain only alphabets.')
    elif len(firstName) < 2 or len(firstName) > 20:
        errors.append('First name should be between 2 and 20 characters.')

    lastName = data.get('lastName')
    if not lastName:
        errors.append('Last name is required.')
    elif not lastName.isalpha():
        errors.append('Last name must contain only alphabets.')
    elif len(lastName) < 2 or len(lastName) > 20:
        errors.append('Last name should be between 2 and 20 characters.')

    patternEmail = re.compile(r'^([A-Za-z0-9_\-\.])+@([A-Za-z0-9_\-\.])+\.([A-Za-z]{2,4})$')
    email = data.get('email')
    if not email:
        errors.append('Email is required.')
    elif not patternEmail.match(email):
        errors.append('Email is invalid.')

    patternPassword = re.compile(r'^(?=.*\d)(?=.*[!@#$%^&*])(?=.*[a-z])(?=.*[A-Z]).{8,20}$')
    password = data.get('password')
    if not password:
        errors.append('Password is required.')
    elif not patternPassword.match(password):
        errors.append(
            'Password should be 8 to 20 characters and contains at least one digit, uppercase, lowercase and special character.')

    rePassword = data.get('rePassword')
    if not rePassword:
        errors.append('Confirm password is required.')
    elif rePassword != password:
        errors.append('Passwords do not match.')
    return errors


def validateLoginForm(data):
    errors = []

    patternEmail = re.compile(r'^([A-Za-z0-9_\-\.])+@([A-Za-z0-9_\-\.])+\.([A-Za-z]{2,4})$')
    email = data.get('email')
    if not email:
        errors.append('Email is required.')
    elif not patternEmail.match(email):
        errors.append('Email is invalid.')

    patternPassword = re.compile(r'^(?=.*\d)(?=.*[!@#$%^&*])(?=.*[a-z])(?=.*[A-Z]).{8,20}$')
    password = data.get('password')
    if not password:
        errors.append('Password is required.')
    elif not patternPassword.match(password):
        errors.append(
            'Password should be 8 to 20 characters and contains at least one digit, uppercase, lowercase and special character.')
    return errors


def validateEmailForForgotPasswordForm(data):
    errors = []

    patternEmail = re.compile(r'^([A-Za-z0-9_\-\.])+@([A-Za-z0-9_\-\.])+\.([A-Za-z]{2,4})$')
    email = data.get('email')
    if not email:
        errors.append('Email is required.')
    elif not patternEmail.match(email):
        errors.append('Email is invalid.')
    return errors


def validateForgotPasswordForm(data):
    errors = []

    lastName = data.get('otp')
    if not lastName:
        errors.append('OTP is required.')

    patternPassword = re.compile(r'^(?=.*\d)(?=.*[!@#$%^&*])(?=.*[a-z])(?=.*[A-Z]).{8,20}$')
    password = data.get('password')
    if not password:
        errors.append('Password is required.')
    elif not patternPassword.match(password):
        errors.append(
            'Password should be 8 to 20 characters and contains at least one digit, uppercase, lowercase and special character.')

    rePassword = data.get('rePassword')
    if not rePassword:
        errors.append('Confirm password is required.')
    elif rePassword != password:
        errors.append('Passwords do not match.')
    return errors


@app.route("/")
def login():
    if 'user_id' in session:
        return render_template('home.html')
    else:
        return render_template('login.html')


@app.route("/home")
def home():
    if 'user_id' in session:
        return render_template('home.html')
    else:
        return render_template('login.html')


@app.route("/loginVerification", methods=['POST', 'GET'])
def login_validation():
    data = request.form.to_dict()
    errors = validateLoginForm(data)

    if not errors:
        email = request.form['email']
        password = request.form['password']

        encryptPass = hashlib.md5(password.encode())
        password = encryptPass.hexdigest()

        query = "SELECT user_id, first_name FROM user WHERE email = %s and password = %s"
        cursor.execute(query, (email, password))

        row = cursor.fetchone()
        con.commit()

        if row is not None:
            session['user_id'] = row[0]
            session['first_name'] = row[1]
            return redirect(url_for('home'))
        else:
            flash('Invalid credentials', 'error')
            return render_template('login.html')
    else:
        for error in errors:
            flash(error, 'error')
        return render_template('login.html')


@app.route("/registration")
def registration():
    if 'user_id' in session:
        return render_template('home.html')
    else:
        return render_template('registration.html')


@app.route("/newUser", methods=['POST', 'GET'])
def newUSer():
    if request.method == 'POST':
        data = request.form.to_dict()
        errors = validateRegistrationForm(data)

        if not errors:
            fName = request.form['firstName']
            lName = request.form['lastName']
            email = request.form['email']
            password = request.form['password']

            encryptPass = hashlib.md5(password.encode())
            password = encryptPass.hexdigest()

            query = "SELECT * FROM user WHERE email = %s"
            cursor.execute(query, (email,))

            row = cursor.fetchone()
            con.commit()

            if row is not None:
                # email is already exists
                flash('Email is already exist, Please use different email !', 'error')
                return redirect(url_for('registration'))

            else:
                cursor.execute("""insert into user (first_name,last_name,email,password) values (%s,%s,%s,%s);""",
                               (fName, lName, email, password))
                con.commit()

                global otp
                otp = random.randint(100000, 999999)

                msg = Message('Textile Design Segmentation', sender='imagesegmentation@outlook.com', recipients=[email])
                msg.body = "Hi " + fName + ",\n\nYour email OTP is: " + str(otp)
                mail.send(msg)

                return render_template('emailVerify.html', email=email)

        else:
            for error in errors:
                flash(error, 'error')
            return redirect(url_for('registration'))
    else:
        return redirect(url_for('home'))


@app.route("/otpVerification", methods=['POST', 'GET'])
def otpVerification():
    if 'user_id' not in session:
        userOTP = request.form.get('otp')
        if otp == int(userOTP):
            flash('You have successfully registered!!', 'success')
            return render_template('login.html')
        else:
            email = request.form.get('email')
            query = "delete from user where email = %s"
            cursor.execute(query, (email,))

            con.commit()
            flash('Email verification failed, Register with valid email or OTP', 'error')
            return redirect(url_for('registration'))
    else:
        return redirect(url_for('home'))


@app.route("/logout")
def logout():
    if 'user_id' in session:
        session.pop("user_id")
        session.pop("first_name")
    return render_template('login.html')


@app.route("/emailForForgotPassword")
def emailForForgotPassword():
    if 'user_id' in session:
        return redirect(url_for('home'))
    else:
        return render_template('emailForForgotPassword.html')


@app.route("/emailVerificationForForgotPassword", methods=['POST', 'GET'])
def emailVerificationForForgotPassword():
    if 'user_id' in session:
        return redirect(url_for('home'))
    elif 'user_id' not in session:
        data = request.form.to_dict()
        errors = validateEmailForForgotPasswordForm(data)

        if not errors:
            email = request.form['email']

            query = "SELECT * FROM user WHERE email = %s"
            cursor.execute(query, (email,))

            row = cursor.fetchone()
            con.commit()

            if row is not None:
                global otpForForgotPassword
                otpForForgotPassword = random.randint(100000, 999999)

                msg = Message('Textile Design Segmentation', sender='imagesegmentation@outlook.com', recipients=[email])
                msg.body = "Hi " + row[1] + ",\n\nYour email OTP for forgot password is: " + str(otpForForgotPassword)
                mail.send(msg)

                return render_template('forgotPassword.html', email=email)

            else:
                flash('Invalid email, Enter registered email', 'error')
                return render_template('emailForForgotPassword.html')
        else:
            for error in errors:
                flash(error, 'error')
            return render_template('emailForForgotPassword.html')

    else:
        return render_template('emailForForgotPassword.html')


@app.route("/forgotPassword", methods=['POST', 'GET'])
def forgotPassword():
    if 'user_id' in session:
        return redirect(url_for('home'))
    elif 'user_id' not in session:
        data = request.form.to_dict()
        errors = validateForgotPasswordForm(data)

        if not errors:
            userOTP = request.form.get('otp')
            if otpForForgotPassword == int(userOTP):
                email = request.form.get('email')
                password = request.form.get('password')

                encryptPass = hashlib.md5(password.encode())
                password = encryptPass.hexdigest()

                query = "UPDATE user SET password = %s WHERE email = %s"
                cursor.execute(query, (password, email))
                con.commit()

                flash('You can login with new password!!', 'success')
                return render_template('login.html')
            else:
                flash('Email verification failed, Try with valid email or OTP', 'error')
                return redirect(url_for('emailForForgotPassword'))
        else:
            for error in errors:
                flash(error, 'error')
            return render_template('forgotPassword.html')


@app.route("/imageSeparation")
def imageSeparation():
    if "user_id" in session:
        return render_template('inputImageData.html')
    else:
        return render_template('login.html')


@app.route("/inputImageData")
def inputImageData():
    if 'user_id' in session:
        return render_template('inputImageData.html')
    else:
        return render_template('login.html')


@app.route("/profile")
def profile():
    if 'user_id' in session:
        user_id = session['user_id']
        query = "select * from user where user_id = %s"
        cursor.execute(query, (user_id,))

        row = cursor.fetchone()
        con.commit()

        if row is not None:
            return render_template('profile.html', firstName=row[1], lastName=row[2], email=row[3])
    else:
        return render_template('login.html')


@app.route("/myPhotos")
def myPhotos():
    if 'user_id' in session:
        user_id = session['user_id']
        query = "select * from user_image where user_id = %s"
        cursor.execute(query, (user_id,))

        data = cursor.fetchall()
        con.commit()
        return render_template('myPhotos.html', data = data)
    else:
        return render_template('login.html')


@app.route("/segmentImage", methods=['POST', 'GET'])
def segmentImage():
    # Check if an image was uploaded
    if 'image' not in request.files:
        flash('No image uploaded', 'error')
        return redirect(url_for('inputImageData'))

    # Get the uploaded image file
    image_file = request.files['image']

    # Validate the file extension
    if image_file.filename == '':
        flash('No image selected', 'error')
        return render_template('inputImageData.html')
    if not allowed_file(image_file.filename):
        flash('Invalid file extension', 'error')
        return render_template('inputImageData.html')

    # Save the image to the upload folder
    filename = secure_filename(image_file.filename)
    image_path = os.path.join('static/uploads/', filename)
    image_file.save(image_path)

    # file = open(image_path, 'rb')
    # inputImageData = file.read()
    # inputImageName = os.path.basename(image_path)
    # inputImageMimetype, encoding = mimetypes.guess_type(image_path)

    # Get segmentation parameters from the form
    points_per_side = int(request.form.get('pointsPerSide'))
    pred_iou_thresh = float(request.form.get('predIouThresh'))
    stability_score_thresh = float(request.form.get('stabilityScoreThresh'))
    crop_n_layers = int(request.form.get('cropNLayers'))
    crop_n_points_downscale_factor = int(request.form.get('cropNPointsDownscaleFactor'))
    min_mask_region_area = int(request.form.get('minMaskRegionArea'))
    output_image_dpi = int(request.form.get('outputImageDpi'))

    # Perform image segmentation
    masks = perform_image_segmentation(
        image_path,
        points_per_side,
        pred_iou_thresh,
        stability_score_thresh,
        crop_n_layers,
        crop_n_points_downscale_factor,
        min_mask_region_area
    )

    # Generate visualization of the segmentation masks
    visualization_path = generate_segmentation_visualization(
        image_path,
        masks,
        output_image_dpi
    )

    # file = open(visualization_path, 'rb')
    # outputImageData = file.read()
    # outputImageName = os.path.basename(visualization_path)
    # outputImageMimetype, encoding = mimetypes.guess_type(visualization_path)

    user_id = session['user_id']
    query = "insert into user_image (input_image_path, output_image_path, user_id) values (%s, %s, %s)"
    cursor.execute(query, (image_path,visualization_path,user_id))
    con.commit()

    # Display the visualization in the result page
    return render_template('result.html', image_path=image_path, visualization_path=visualization_path)


# Helper function to check allowed file extensions
def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# Helper function to perform image segmentation
def perform_image_segmentation(
        image_path,
        points_per_side,
        pred_iou_thresh,
        stability_score_thresh,
        crop_n_layers,
        crop_n_points_downscale_factor,
        min_mask_region_area
):
    image = cv2.imread(image_path)
    image = cv2.cvtColor(image, cv2.COLOR_BGR2RGB)

    mask_generator = SamAutomaticMaskGenerator(
        model=sam,
        points_per_side=points_per_side,
        pred_iou_thresh=pred_iou_thresh,
        stability_score_thresh=stability_score_thresh,
        crop_n_layers=crop_n_layers,
        crop_n_points_downscale_factor=crop_n_points_downscale_factor,
        min_mask_region_area=min_mask_region_area
    )

    masks = mask_generator.generate(image)

    return masks


def generate_segmentation_visualization(
        image_path,
        masks,
        output_image_dpi,
):
    image = Image.open(image_path)
    image_size = image.size
    canvas = np.zeros_like(image)

    for ann in masks:
        m = ann['segmentation']
        color_mask = np.random.rand(1, 1, 3) * 255
        canvas[np.where(m)] = color_mask

    fig, ax = plt.subplots(figsize=(image_size[0] / output_image_dpi, image_size[1] / output_image_dpi),
                           dpi=output_image_dpi)
    ax.imshow(canvas.astype(np.uint8))
    ax.axis('off')
    plt.tight_layout(pad=0)

    # Save the image to a file
    image_name = os.path.basename(image_path)
    visualization_filename = f'{image_name}_visualization.png'
    visualization_path = os.path.join(app.config['UPLOAD_FOLDER'], visualization_filename)
    plt.savefig(visualization_path, bbox_inches='tight', pad_inches=0, dpi=output_image_dpi)
    plt.close()

    return visualization_path


if __name__ == "__main__":
    if getattr(sys, 'frozen', False):
        # Running as an executable (PyInstaller)
        sys.stdout = open(os.devnull, 'w')
        sys.stderr = open(os.devnull, 'w')
    app.run(debug=True)
