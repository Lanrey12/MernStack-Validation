const mongoose = require('mongoose');
const jwt = require('jsonwebtoken')
const crypto = require("crypto");
const Role = require('../models/role')
const bcrypt = require('bcrypt')
const  secret  = require('../config.js');
const sendEmail = require('../services/send-Email')



const Schema = mongoose.Schema;

const AccountSchema = new Schema({
    email: { 
        type: String, 
        unique: true, 
        required: true, 
    },
    password: {
        type: String,
        required: true,
        minlength: 5
    },
    title: { 
        type: String,  
    },
    firstName: { 
        type: String, 
        required: true 
    },
    lastName: { 
        type: String, 
        required: true 
    },
    location: {
        type: String,
    },
    bio: {
          type: String,
    },
    website: {
        type: String,
    },
    imageUrl: {
        type: String,
    },
    acceptTerms: { type: Boolean },
    role: { 
        type: String, 
        required: true 
    },
    verificationToken: { type: String },
    isVerified: { type: Boolean, default: false },
    resetToken: { type: String },
    resetTokenExpiry: { type: Date },
    dateCreated: { type: Date, default: Date.now },
    dateUpdated: { type: Date }
});

AccountSchema.set('toJSON', {
    virtuals: true,
    versionKey: false,
    transform: function (doc, ret) {
        // remove these props when object is serialized
        delete ret._id;
    }
});
const accountSchema = mongoose.model('accountSchema',  AccountSchema);



function isValidId(id) {
    return mongoose.Types.ObjectId.isValid(id);
}

///helper functions
function generateToken() {
    return crypto.randomBytes(40).toString('hex');
}

function hash(password){
    return bcrypt.hashSync(password, 10)
}


function sendVerificationEmail(account, origin) {
    let message;
    if (origin) {
        const verifyUrl = `${origin}/account/verify-email?token=${account.verificationToken}`;
        message = `<p>Please click the below link to verify your email address:</p>
                   <p><a href="${verifyUrl}">${verifyUrl}</a></p>`;
    } else {
        message = `<p>Please use the below token to verify your email address with the <code>/account/verify-email</code> api route:</p>
                   <p><code>${account.verificationToken}</code></p>`;
    }

    sendEmail({
        to: account.email,
        subject: 'Sign-up Verification API - Verify Email',
        html: `<h4>Verify Email</h4>
               <p>Thanks for registering!</p>
               ${message}`
    });
}

function sendAlreadyRegisteredEmail(email, origin) {
    let message;
    if (origin) {
        message = `<p>If you don't know your password please visit the <a href="${origin}/account/forgot-password">forgot password</a> page.</p>`;
    } else {
        message = `<p>If you don't know your password you can reset it via the <code>/account/forgot-password</code> api route.</p>`;
    }

    sendEmail({
        to: email,
        subject: 'Sign-up Verification API - Email Already Registered',
        html: `<h4>Email Already Registered</h4>
               <p>Your email <strong>${email}</strong> is already registered.</p>
               ${message}`
    });
}


function sendPasswordResetEmail(account, origin) {
    let message;
    if (origin) {
        const resetUrl = `${origin}/account/reset-password?token=${account.resetToken}`;
        message = `<p>Please click the below link to reset your password, the link will be valid for 1 day:</p>
                   <p><a href="${resetUrl}">${resetUrl}</a></p>`;
    } else {
        message = `<p>Please use the below token to reset your password with the <code>/account/reset-password</code> api route:</p>
                   <p><code>${account.resetToken}</code></p>`;
    }

    sendEmail({
        to: account.email,
        subject: 'Sign-up Verification API - Reset Password',
        html: `<h4>Reset Password Email</h4>
               ${message}`
    });
}

//basic details
function basicDetails(account) {
    const { id, title, firstName, lastName, email, role, location, bio, website, imageUrl, dateCreated, dateUpdated } = account;
    return { id, title, firstName, lastName, email, role, location, bio, website, imageUrl, dateCreated, dateUpdated };
}

///functions 

async function register(params, origin){
    if(await accountSchema.findOne({ email: params.email})){
          return sendAlreadyRegisteredEmail(params.email, origin)
    }
    const account = new accountSchema(params)

    const isFirstAccount = (await accountSchema.countDocuments({})) === 0;
    account.role = isFirstAccount ? Role.Admin : Role.User 
    account.verificationToken = generateToken();
    account.isVerified = false;

    if(params.password){
        account.password = hash(params.password)
    }

    await account.save()
  
    sendVerificationEmail(account, origin);
  
}
// to verify the user email 
async function verifyEmail({ token }){
    const account = await accountSchema.findOne({ verificationToken: token })
    if(!account) throw 'Verification failed' 
    account.isVerified = true;
    await account.save()
}
// login function
async function authenticate({ email, password }){
      const account = await accountSchema.findOne({ email, isVerified: true})
      if(account && bcrypt.compareSync(password, account.password)){
        const token = jwt.sign({ sub: account.id, id: account.id }, secret.secret);
        return { ...basicDetails(account), token };
      }
}

//forgot password function
async function forgotPassword({email}, origin){
    const account = await accountSchema.findOne({email})
    if(!account) return 

    account.resetToken = generateToken()
    account.resetTokenExpiry = new Date(Date.now() +  24*60*60*1000).toISOString()
    account.save()

    sendPasswordResetEmail(account, origin)
}
//////////////////////////
async function validateResetToken({ token }) {
    const account = await accountSchema.findOne({ 
        resetToken: token,
        resetTokenExpiry: { $gt: new Date() }
    });
    
    if (!account) throw 'Invalid token';
}
//////////////////////////
async function resetPassword({ password, token}){
    const account = await accountSchema.findOne({ 
        resetToken: token,
        resetTokenExpiry: { $gt: new Date() }
    })
    if(!account) throw "Invalid Token"

    account.password = hash(password)
    account.isVerified = true;
    account.resetToken = undefined;
    account.resetTokenExpiry = undefined;
     
    await account.save()
}
//////////////////////////
async function getAccounts(){
    const account = await accountSchema.find()
    return account.map(account => basicDetails(account))
}

////////////
async function getAccount(id){
    if(!isValidId(id)) throw 'Account id is not valid'
    const account = await accountSchema.findById(id)
    if(!account) throw 'Account does not exist'
    return account
}
async function getAccountById(id){
    const account = await getAccount(id)
    return basicDetails(account)
}
/////////////////
////for admin to create new users
async function create(params){
    if ( await accountSchema.findOne({ email: params.email })){
        throw 'Email " ' + params.email + '  "is already registered'
    }
    const account = new accountSchema(params)
    account.isVerified = true

    if(params.password){
        account.password = hash(params.password)
    }
    await account.save()
    return basicDetails(account)
}
/////////////////
async function update( id, params ){

    const account = await getAccount(id)

    if (account.email !== params.email && await accountSchema.findOne({ email: params.email })) {
        throw 'Email "' + params.email + '" is already taken';
    }

    if(params.password){
        account.password = hash(params.password)
    }

    Object.assign(account, params)
    account.dateUpdated = Date.now()
    await account.save()
    return basicDetails(account)
}

async function _delete(id){
    const account = await getAccount(id)
    await account.remove()
}



module.exports =  { 
    accountSchema,
    register,
    verifyEmail,
    authenticate,
    forgotPassword,
    validateResetToken,
    resetPassword,
    getAccounts,
    getAccountById,
    create,
    update,
    delete: _delete
}