#!/usr/bin/python
# -*- coding: utf-8 -*-
from flask import Flask, render_template, request, redirect, jsonify, \
    url_for, flash
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Catalog, Item, User
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests
from functools import wraps

app = Flask(__name__)

Json_data = json.loads(open('client_secrets.json', 'r').read())
CLIENT_ID = Json_data['web']['client_id']
APPLICATION_NAME = 'Catalog Application'

# Connect to Database and create database session

engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# Login and user account functions

def login_required(f):

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in login_session:
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function


# Create anti-forgery state token

@app.route('/login')
def showLogin():
    state = ''.join(
        random.choice(string.ascii_uppercase + string.digits)
        for x in xrange(32))
    login_session['state'] = state

    # return "The current session state is %s" % login_session['state']

    return render_template('login.html', STATE=state)


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print 'access token received %s ' % access_token

    app_id = json.loads(open('fb_client_secrets.json', 'r').read())['web']['app_id']
    app_secret = json.loads(open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = \
        'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' \
        % (app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API

    userinfo_url = 'https://graph.facebook.com/v2.8/me'
    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = \
        'https://graph.facebook.com/v2.8/me?access_token=%s&fields=name,id,email' \
        % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result

    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data['name']
    login_session['email'] = data['email']
    login_session['facebook_id'] = data['id']

    # The token must be stored in the login_session in order to properly logout

    login_session['access_token'] = token

    # Get user picture

    url = \
        'https://graph.facebook.com/v2.8/me/picture?access_token=%s&redirect=0&height=200&width=200' \
        % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data['data']['url']

    # see if user exists

    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += \
        ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    flash('Now logged in as %s' % login_session['username'])
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']

    # The access token must me included to successfully logout

    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' \
        % (facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return 'you have been logged out'


@app.route('/gconnect', methods=['POST'])
def gconnect():

    # Validate state token

    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'
                                 ), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Obtain authorization code

    code = request.data

    try:

        # Upgrade the authorization code into a credentials object

        oauth_flow = flow_from_clientsecrets('client_secrets.json',
                scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = \
            make_response(json.dumps('Failed to upgrade the authorization code.'
                          ), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.

    access_token = credentials.access_token
    url = \
        'https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' \
        % access_token
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])

    # If there was an error in the access token info, abort.

    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.

    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = \
            make_response(json.dumps("Token's user ID doesn't match given user ID."
                          ), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.

    if result['issued_to'] != CLIENT_ID:
        response = \
            make_response(json.dumps("Token's client ID does not match app's."
                          ), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = \
            make_response(json.dumps('Current user is already connected.'
                          ), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.

    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info

    userinfo_url = 'https://www.googleapis.com/oauth2/v1/userinfo'
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # ADD PROVIDER TO LOGIN SESSION

    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one

    user_id = getUserID(data['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += \
        ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash('you are now logged in as %s' % login_session['username'])
    print 'done!'
    return output


# DISCONNECT - Revoke a current user's token and reset their login_session

@app.route('/gdisconnect')
def gdisconnect():

    # Only disconnect a connected user.

    access_token = login_session['access_token']

    # access_token = login_session.get('access_token')

    if access_token is None:
        response = \
            make_response(json.dumps('Current user not connected.'),
                          401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' \
        % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        response = make_response(json.dumps('Successfully disconnected.'
                                 ), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = \
            make_response(json.dumps('Failed to revoke token for given user.',400))
        response.headers['Content-Type'] = 'application/json'
        return response


# Disconnect based on provider

@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash('You have successfully been logged out.')
        return redirect(url_for('showCatalogs'))
    else:
        flash('You were not logged in')
        return redirect(url_for('showCatalogs'))


# User Helper Functions

def createUser(login_session):
    newUser = User(name=login_session['username'],
                   email=login_session['email'],
                   picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email'
            ]).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


# JSON APIs Functions

@app.route('/catalog/JSON')
def CatalogsJSON():
    Catalogs = session.query(Catalog).all()
    return jsonify(Catalogs=[c.serialize for c in Catalogs])


@app.route('/catalog/<int:catalog_id>/JSON')
def CatalogItemJSON(catalog_id):
    items = session.query(Item).filter_by(catalog_id=catalog_id).all()
    return jsonify(Catalogs=[i.serialize for i in items])


@app.route('/catalog/<int:catalog_id>/item/<int:item_id>/JSON')
def ItemJSON(catalog_id, item_id):
    item = session.query(item).filter_by(id=item_id).one()
    return jsonify(Item=item.serialize)


# Show all Catalogs

@app.route('/')
@app.route('/catalog/')
def showCatalogs():
    catalogs = session.query(Catalog).order_by(asc(Catalog.name))
    items = session.query(Item).order_by(Item.id.desc())
    if 'username' not in login_session:
        return render_template('publiccatalogs.html',
                               catalogs=catalogs, items=items)
    else:
        return render_template('catalogs.html', catalogs=catalogs,
                               items=items)


# Show a Catalog

@app.route('/catalog/<string:catalog_name>/')
def showCatalog(catalog_name):
    currentCatalog = \
        session.query(Catalog).filter_by(name=catalog_name).one()
    items = \
        session.query(Item).filter_by(catalog_id=currentCatalog.id).all()
    catalogs = session.query(Catalog).order_by(asc(Catalog.name))
    if 'username' not in login_session:
        return render_template('publicsinglecatalog.html', items=items,
                               catalogs=catalogs,
                               catalog=currentCatalog)
    else:

        return render_template('singlecatalog.html', items=items,
                               catalogs=catalogs,
                               catalog=currentCatalog)


# Create a new Catalog


@app.route('/catalog/new/', methods=['GET', 'POST'])
@login_required
def newCatalog():
    if request.method == 'POST':
        isCurrentCatExist = \
            session.query(Catalog).filter_by(name=request.form['name'
                ]).count()
        if isCurrentCatExist == 0:
            newCatalog = Catalog(name=request.form['name'],
                                 user_id=login_session['user_id'])
            session.add(newCatalog)
            flash('New Catalog %s Successfully Created'
                  % newCatalog.name)
            session.commit()
            return redirect(url_for('showCatalogs'))
        else:
            flash('Catalog name already exist')
            return render_template('newcatalog.html',
                                   name=request.form['name'])
    else:
        return render_template('newcatalog.html')


# Edit a Catalog


@app.route('/catalog/<string:catalog_name>/edit/', methods=['GET',
           'POST'])
@login_required
def editCatalog(catalog_name):
    editedCatalog = \
        session.query(Catalog).filter_by(name=catalog_name).one()
    if editedCatalog.user_id != login_session['user_id']:
        flash('You are not authorized to edit %s Catalog.Please create your own catalog in order to edit.' % editedCatalog.name)
        return render_template('newcatalog.html')
    if request.method == 'POST':
        if request.form['name']:
            isCurrentCatExist = \
                session.query(Catalog).filter_by(name=request.form['name'
                    ]).count()
            if isCurrentCatExist == 0:
                editedCatalog.name = request.form['name']
                flash('Catalog Successfully Edited %s'
                      % editedCatalog.name)
                return redirect(url_for('showCatalogs'))
            else:
                flash('Catalog name already exist')
                return render_template('editCatalog.html',
                        catalog=editedCatalog)
    else:
        return render_template('editCatalog.html',
                               catalog=editedCatalog)


# Delete a Catalog


@app.route('/catalog/<string:catalog_name>/delete/', methods=['GET',
           'POST'])
@login_required
def deleteCatalog(catalog_name):
    CatalogToDelete = \
        session.query(Catalog).filter_by(name=catalog_name).one()
    if CatalogToDelete.user_id != login_session['user_id']:
        flash('You are not authorized to delete %s Catalog.Please create your own catalog in order to delete.' % CatalogToDelete.name)
        return render_template('newcatalog.html')
    if request.method == 'POST':
        items = \
            session.query(Item).filter_by(catalog_id=CatalogToDelete.id).all()
        for item in items:
            session.delete(item)
        session.delete(CatalogToDelete)
        flash('%s Successfully Deleted' % CatalogToDelete.name)
        session.commit()
        return redirect(url_for('showCatalogs'))
    else:
        return render_template('deleteCatalog.html',
                               catalog=CatalogToDelete)


# Item related functions

@app.route('/catalog/<string:catalog_name>/<string:item_name>/')
def showItem(catalog_name, item_name):
    item = session.query(Item).filter_by(name=item_name).one()
    if 'username' not in login_session:
        return render_template('publicitem.html', item=item)
    else:
        return render_template('item.html', item=item)


# Create a new menu item


@app.route('/items/new/', methods=['GET', 'POST'])
@login_required
def newItem():
    if request.method == 'POST':
        isCurrentItemExist = \
            session.query(Item).filter_by(name=request.form['name'
                ]).count()
        if isCurrentItemExist == 0:
            newItem = Item(name=request.form['name'],
                           description=request.form['description'],
                           catalog_id=request.form['catalog'])
            session.add(newItem)
            session.commit()
            flash('New %s Item Successfully Created' % newItem.name)
            return redirect(url_for('showCatalogs'))
        else:
            flash('Item name already exist')
            catalogs = \
                        session.query(Catalog).order_by(asc(Catalog.name))
            return render_template('newitem.html', catalogs=catalogs,
                                   name=request.form['name'],
                                   description=request.form['description'
                                   ])
    else:
        catalogs = session.query(Catalog).order_by(asc(Catalog.name))
        return render_template('newitem.html', catalogs=catalogs)


# Edit a menu item


@app.route('/catalog/<string:catalog_name>/<string:item_name>/edit',
           methods=['GET', 'POST'])
@login_required
def editItem(item_name, catalog_name):
    editedItem = session.query(Item).filter_by(name=item_name).one()
    if request.method == 'POST':
        if editedItem.user_id != login_session['user_id']:
            flash('You are not authorized to edit %s Item.Please create your own item in order to edit.' % editedItem.name)
            return render_template('newcatalog.html')
        if request.form['name']:
            isCurrentItemExist = session
            .query(Item)
            .filter_by(name=request.form['name'])
            .count()
            if isCurrentItemExist == 0:
                editedItem.name = request.form['name']
                if request.form['description']:
                    editedItem.description = request.form['description']
                if request.form['catalog']:
                    editedItem.catalog_id = request.form['catalog']
                session.add(editedItem)
                session.commit()
                flash('%s Item Successfully Updated' % editedItem.name)
                return redirect(url_for('showItem',
                                item_name=editedItem.name,
                                catalog_name=editedItem.catalog.name))
            else:
                flash('Item name already exist')
                catalogs = \
                    session.query(Catalog).order_by(asc(Catalog.name))
                return render_template('editItem.html',
                        item=editedItem, catalogs=catalogs,
                        catalog_name=editedItem.catalog.name)
        else:
            flash('Item name is required')
            catalogs = \
                session.query(Catalog).order_by(asc(Catalog.name))
            return render_template('editItem.html', item=editedItem,
                                   catalogs=catalogs,
                                   catalog_name=editedItem.catalog.name)
    else:
        catalogs = session.query(Catalog).order_by(asc(Catalog.name))
        return render_template('editItem.html', item=editedItem,
                               catalogs=catalogs,
                               catalog_name=editedItem.catalog.name)


# Delete a menu item


@app.route('/catalog/<string:catalog_name>/<string:item_name>/delete',
           methods=['GET', 'POST'])
@login_required
def deleteItem(catalog_name, item_name):
    itemToDelete = session.query(Item).filter_by(name=item_name).one()
    if itemToDelete.user_id != login_session['user_id']:
        flash('You are not authorized to delete %s Item.Please create your own item in order to delete.' % itemToDelete.name)
        return render_template('newcatalog.html')
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash('Item Successfully Deleted')
        return redirect(url_for('showCatalogs'))
    else:
        return render_template('deleteItem.html', item=itemToDelete)

if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5004)
