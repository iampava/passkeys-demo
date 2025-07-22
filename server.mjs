/*
 * @license
 * Copyright 2023 Google Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 */

// init project
import path from 'path';
import url from 'url';
const __dirname = url.fileURLToPath(new URL('.', import.meta.url));
import express from 'express';
import session from 'express-session';
import hbs from 'express-handlebars';
const app = express();
import useragent from 'express-useragent';
import { FirestoreStore } from '@google-cloud/connect-firestore';
import { config, store } from './config.js';
import { auth } from './libs/auth.mjs';
import { Projects, Credentials, Users } from './libs/db.mjs';
import { verifyAuthenticationResponse } from '@simplewebauthn/server';
import { isoBase64URL } from '@simplewebauthn/server/helpers';

const is_localhost = process.env.NODE_ENV === 'localhost';
const title = config.rp_name;
const project_name = config.project_name;

const views = path.join(__dirname, 'views');
app.set('view engine', 'html');
app.engine('html', hbs.engine({
  extname: 'html',
  defaultLayout: 'index',
  layoutsDir: path.join(views, 'layouts'),
  partialsDir: path.join(views, 'partials'),
}));
app.set('views', './views');
app.use(express.json());
app.use(useragent.express());
app.use(express.static('public'));
app.use(express.static('dist'));
app.use(session({
  secret: config.secret, 
  resave: true,
  saveUninitialized: false,
  proxy: true,
  store: new FirestoreStore({
    dataset: store,
    kind: 'express-sessions',
  }),
  cookie:{
    path: '/',
    httpOnly: true,
    secure: !is_localhost,
    maxAge: 1000 * 60 * 60 * 24 * 365, // 1 year
  }
}));

app.use((req, res, next) => {
  res.locals.project_name = config.project_name;
  res.locals.title = config.rp_name;
  res.locals.github_repository = 'https://github.com/GoogleChromeLabs/passkeys-demo';
  return next();
});

app.get('/', (req, res) => {
  // Check session
  if (req.session.username) {
    // If username is known, redirect to `/reauth`.
    return res.redirect(307, '/reauth');
  }
  // If the user is not signed in, show `index.html` with id/password form.
  return res.render('index.html');
});

app.get('/one-button', (req, res) => {
  // Check session
  if (req.session.username) {
    // If username is known, redirect to `/reauth`.
    return res.redirect(307, '/reauth');
  }
  // If the user is not signed in, show `index.html` with id/password form.
  return res.render('one-button.html', {
    project_name,
    title,
  });
});

app.get('/reauth', (req, res) => {
  const username = req.session.username;
  if (!username) {
    return res.redirect(302, '/');
  }
  // Show `reauth.html`.
  // User is supposed to enter a password (which will be ignored)
  // Make XHR POST to `/signin`
  return res.render('reauth.html', {
    username: username,
    project_name,
    title,
  });
});

app.get('/home', (req, res) => {
  if (!req.session.username || req.session['signed-in'] != 'yes') {
    // If user is not signed in, redirect to `/`.
    return res.redirect(307, '/');
  }
  // `home.html` shows sign-out link
  return res.render('home.html', {
    displayName: req.session.username,
    project_name,
    title,
  });
});

app.get('/.well-known/assetlinks.json', (req, res) => {
  const assetlinks = [];
  for (let domain of config.associated_domains) {
    if (domain?.sha256_cert_fingerprints) {
      assetlinks.push({
        relation: ['delegate_permission/common.get_login_creds'],
        target: {
          namespace: 'android_app',
          package_name: domain.package_name,
          sha256_cert_fingerprints: [ domain.sha256_cert_fingerprints ]
        },
      });
    } else {
      assetlinks.push({
        relation: ['delegate_permission/common.get_login_creds'],
        target: {
          namespace: 'web',
          site: domain,
        },
      });
    }
  }
  return res.json(assetlinks);
});

app.get('/.well-known/passkey-endpoints', (req, res) => {
  const web_endpoint = `${config.origin}/home`;
  return res.json({ enroll: web_endpoint, manage: web_endpoint });
});

app.get('/api/projects', async (req, res) => {
  try {
    const projects = await Projects.list();
    return res.json(projects);
  } catch (error) {
    console.error('Failed to fetch projects:', error);
    return res.status(500).json({ error: 'Failed to fetch projects' });
  }
});

app.put('/api/projects/:id/color', async (req, res) => {
  try {
    // Check if user is signed in
    if (!req.session['signed-in'] || !req.session.username) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    
    const { id } = req.params;
    const { color, authResponse } = req.body;
    
    if (!color) {
      return res.status(400).json({ error: 'Color is required' });
    }
    
    if (!authResponse) {
      return res.status(400).json({ error: 'Passkey authentication required' });
    }
    
    // Verify the passkey authentication
    const expectedChallenge = req.session.challenge;
    if (!expectedChallenge) {
      return res.status(400).json({ error: 'No authentication challenge found. Please authenticate first.' });
    }
    
    const expectedOrigin = config.associated_origins;
    const expectedRPID = config.hostname;
    
    // Find the matching credential from the credential ID
    const cred = await Credentials.findById(authResponse.id);
    if (!cred) {
      return res.status(404).json({ error: 'Credential not found' });
    }
    
    // Verify the credential belongs to the current user
    const user = await Users.findById(cred.user_id);
    if (!user || user.username !== req.session.username) {
      return res.status(403).json({ error: 'Invalid credential for current user' });
    }
    
    // Construct the credential object for verification
    const credential = {
      id: cred.id,
      publicKey: isoBase64URL.toBuffer(cred.publicKey),
      transports: cred.transports,
    };
    
    // Verify the authentication response
    const verification = await verifyAuthenticationResponse({
      response: authResponse,
      expectedChallenge,
      expectedOrigin,
      expectedRPID,
      credential,
      requireUserVerification: false,
    });
    
    if (!verification.verified) {
      return res.status(403).json({ error: 'Authentication verification failed' });
    }
    
    // Clear the challenge after successful verification
    delete req.session.challenge;
    
    // Update the project color
    await Projects.updateColor(id, color);
    return res.json({ success: true });
  } catch (error) {
    console.error('Failed to update project color:', error);
    return res.status(500).json({ error: 'Failed to update project color' });
  }
});

app.use('/auth', auth);

async function initializeProjects() {
  try {
    const existingProjects = await Projects.list();
    if (existingProjects.length === 0) {
      const dummyProjects = [
        { name: 'Website Redesign', color: '#FF6B6B' },
        { name: 'Mobile App', color: '#4ECDC4' },
        { name: 'API Development', color: '#45B7D1' }
      ];
      
      for (const project of dummyProjects) {
        await Projects.add(project);
      }
      console.log('Initialized database with dummy projects');
    }
  } catch (error) {
    console.error('Failed to initialize projects:', error);
  }
}

const listener = app.listen(process.env.PORT || 8080, async () => {
  console.log('Your app is listening on port ' + listener.address().port);
  await initializeProjects();
});
