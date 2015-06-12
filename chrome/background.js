/**
 * @license
 * Copyright 2011 Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @fileoverview Receives potential passwords from content_script.js and checks
 * to see if they're the user's password. Populates localStorage with partial
 * hashes of the user's password.
 * @author adhintz@google.com (Drew Hintz)
 * @author mignacio@fb.com (Mark Ignacio)
 */

'use strict';

goog.provide('passwordalert.background');

goog.require('goog.crypt');
goog.require('goog.crypt.Sha1');
goog.require('passwordalert.keydown.Typed');


/**
 * Key for localStorage to store salt value.
 * @private {string}
 * @const
 */
passwordalert.background.SALT_KEY_ = 'salt';


/**
 * Number of bits of the hash to use.
 * @private {number}
 * @const
 */
passwordalert.background.HASH_BITS_ = 37;


/**
 * Object that holds configurations for specified websites.
 * @private
 * @type {{Facebook: {loginURL: RegExp, loginInitURL: string, emailDomain:
 *     undefined, displayUserAlert_: boolean, reportURL: undefined,
 *     shouldInitializePassword: boolean, securityEmailAddress: string,
 *     minimumLength: number, initialized: undefined}}}
 */
passwordalert.background.SITES_ = {
  Facebook: {
    loginURL: /^https:\/\/[a-z\-]+\.facebook\.com(\/|\/login\.php)?$/,
    loginInitURL: 'https://www.facebook.com/',
    emailDomain: undefined,
    displayUserAlert_: true,
    reportURL: undefined,
    shouldInitializePassword: true,
    securityEmailAddress: 'phish@fb.com',
    minimumLength: 6,

    // Not config defined; this is used for the initialization notification.
    initialized: undefined
  }
};


/**
 * Minimum length of passwords.
 * @private {number}
 * @const
 */
passwordalert.background.MINIMUM_PASSWORD_ = Number.MAX_VALUE;


/**
 * Maximum character typing rate to protect against abuse.
 * Calculated for 60 wpm at 5 cpm for one hour.
 * @private {number}
 * @const
 */
passwordalert.background.MAX_RATE_PER_HOUR_ = 18000;


/**
 * How many passwords have been checked in the past hour.
 * @private {number}
 */
passwordalert.background.rateLimitCount_ = 0;


/**
 * The time when the rateLimitCount_ will be reset.
 * @private {Date}
 */
passwordalert.background.rateLimitResetDate_;


/**
 * Associative array of possible passwords. Keyed by tab id.
 * @private {Object.<number, Object.<string, string|boolean>>}
 */
passwordalert.background.possiblePassword_ = {};


/**
 * Associative array of state for Keydown events.
 * @private {passwordalert.background.State_}
 */
passwordalert.background.stateKeydown_ = {
  'hash': '',
  'otpCount': 0,
  'otpMode': false,
  'otpTime': null,
  'typed': new passwordalert.keydown.Typed(),
  'typedTime': null
};


/**
 * Associative array of state for Keydown events.
 * @private {passwordalert.background.State_}
 */
passwordalert.background.stateKeypress_ = {
  'hash': '',
  'otpCount': 0,
  'otpMode': false,
  'otpTime': null,
  'typed': '',
  'typedTime': null
};


/**
 * Password lengths for passwords that are being watched.
 * If an array offset is true, then that password length is watched.
 * @private {Array.<boolean>}
 */
passwordalert.background.passwordLengths_;


/**
 * If no key presses for this many seconds, flush buffer.
 * @private {number}
 * @const
 */
passwordalert.background.SECONDS_TO_CLEAR_ = 10;


/**
 * OTP must be typed within this time since the password was typed.
 * @private {number}
 * @const
 */
passwordalert.background.SECONDS_TO_CLEAR_OTP_ = 60;


/**
 * Number of digits in a valid OTP.
 * @private {number}
 */
passwordalert.background.OTP_LENGTH_ = 6;


/**
 * ASCII code for enter character.
 * @private {number}
 * @const
 */
passwordalert.background.ENTER_ASCII_CODE_ = 13;


/**
 * Request from content_script. action is always defined. Other properties are
 * only defined for certain actions.
 * @typedef {{action: string, email: (string|undefined),
 *            password: (string|undefined), url: (string|undefined),
 *           looksLikeGoogle: (string|undefined), site: (string|undefined)}}
 * @private
 */
passwordalert.background.Request_;


/**
 * State of keypress or keydown events.
 * @typedef {{hash: string, otpCount: number, otpMode: boolean,
 *            otpTime: Date, typed: (passwordalert.keydown.Typed|string),
 *            typedTime: Date}}
 * @private
 */
passwordalert.background.State_;


/**
 * Namespace for chrome's managed storage.
 * @private {string}
 * @const
 */
passwordalert.background.MANAGED_STORAGE_NAMESPACE_ = 'managed';


/**
 * Is password alert used in enterprise environment.  If false, then it's
 * used by individual consumer.
 * @private {boolean}
 */
passwordalert.background.enterpriseMode_ = false;


/**
 * The id of the chrome notification that prompts the user to initialize
 * their password.
 * @private {string}
 * @const
 */
passwordalert.background.NOTIFICATION_ID_ =
    'initialize_password_notification';


/**
 * Key for the allowed hosts object in chrome storage.
 * @private {string}
 * @const
 */
passwordalert.background.ALLOWED_HOSTS_KEY_ = 'allowed_hosts';


/**
 * Whether the extension was newly installed.
 * @private {boolean}
 */
passwordalert.background.isNewInstall_ = false;


/**
 * Whether the background page is initialized (managed policy loaded).
 * @private {boolean}
 */
passwordalert.background.isInitialized_ = false;


/**
 * This sets the state of new install that can be used later.
 * @param {!Object} details Details of the onInstall event.
 * @private
 */
passwordalert.background.handleNewInstall_ = function(details) {
  if (details['reason'] == 'install') {
    console.log('New install detected.');
    passwordalert.background.isNewInstall_ = true;
    passwordalert.background.initializePasswordIfReady_();
  }
};


/**
 * Set the managed policy values into the configurable variables.
 * @param {function()} callback Executed after policy values have been set.
 * @private
 */
passwordalert.background.setManagedPolicyValuesIntoConfigurableVariables_ =
    function(callback) {
  chrome.storage.managed.get(function(managedPolicy) {
    if (Object.keys(managedPolicy).length == 0) {
      passwordalert.isEnterpriseUse_ = false;
    } else {
      // nb: overwrites any existing policies
      managedPolicy.forEach(function(managedSite) {
        var newPolicy = {};
        var policyName = managedSite['name'];
        for (var key in managedSite) {
          if (!managedSite.hasOwnProperty(key)) continue;

          // strings and regex only~
          var value = managedSite[key];
          if (typeof value === 'string' || value instanceof RegExp) {
            newPolicy[key] = value;
          }
        }
        passwordalert.background.SITES_[policyName] = managedSite;
      });
    }
    callback();
  });
};


/**
 * Handle managed policy changes by updating the configurable variables.
 * @param {!Object} changedPolicies Object mapping each policy to its
 *     new values.  Policies that have not changed will not be present.
 *     For example:
 *     {
 *      report_url: {
 *        newValue: "https://passwordalert222.example.com/report/"
 *        oldValue: "https://passwordalert111.example.com/report/"
 *        }
 *     }
 * @param {!string} storageNamespace The name of the storage area
 *     ("sync", "local" or "managed") the changes are for.
 * @private
 */
passwordalert.background.handleManagedPolicyChanges_ =
    function(changedPolicies, storageNamespace) {
  if (storageNamespace ===
      passwordalert.background.MANAGED_STORAGE_NAMESPACE_) {
    console.log('Handling changed policies.');
    Object.keys(changedPolicies).forEach(function(changedPolicy) {
      if (!passwordalert.background.isEnterpriseUse_) {
        passwordalert.background.isEnterpriseUse_ = true;
        console.log('Enterprise use enabled via updated managed policy.');
      }

      passwordalert.background.SITES_[changedPolicy] =
          changedPolicies[changedPolicy]['newValue'];
    });
  }
};


/**
 * Programmatically inject the content script into all existing tabs that
 * belongs to the user who has just installed the extension.
 * https://developer.chrome.com/extensions/content_scripts#pi
 *
 * The programmatically injected script will be replaced by the
 * normally injected script when a tab reloads or loads a new url.
 * @param {function()} callback Executed after content scripts have been
 *     injected, e.g. user to initialize password.
 * @private
 */
passwordalert.background.injectContentScriptIntoAllTabs_ =
    function(callback) {
  chrome.tabs.query({}, function(tabs) {
    for (var i = 0; i < tabs.length; i++) {
      // Skip chrome:// and chrome-devtools:// pages
      if (tabs[i].url.lastIndexOf('chrome', 0) != 0) {
        chrome.tabs.executeScript(tabs[i].id,
                                  {file: 'content_script_compiled.js'});
      }
    }
    callback();
  });
};


/**
 * Display the notification for user to initialize their password.
 * If a notification has not been created, a new one is created and displayed.
 * If a notification has already been created, it will be updated and displayed.
 *
 * A trick is used to make the notification display again --
 * essentially updating it to a higher priority (> 0).
 * http://stackoverflow.com/a/26358154/2830207
 * @private
 */
passwordalert.background.displayInitializePasswordNotification_ = function() {
  chrome.notifications.getAll(function(notifications) {
    if (notifications[passwordalert.background.NOTIFICATION_ID_]) {
      chrome.notifications.update(passwordalert.background.NOTIFICATION_ID_,
          {priority: 2}, function() {});
    } else {
      var siteNames = [];
      var loginURLs = [];
      Object.keys(passwordalert.background.SITES_).forEach(function(siteName) {
        var site = passwordalert.background.SITES_[siteName];
        siteNames.push(siteName);
        if (!site.initialized) {
          if (site.loginURL instanceof RegExp) {
            loginURLs.push(site.loginInitURL);
          }
          else {
            loginURLs.push(site.loginURL);
          }
        }
      });
      siteNames = siteNames.join(', ');
      var options = {
        type: 'basic',
        priority: 1,
        title: chrome.i18n.getMessage('extension_name') + ' - ' + siteNames,
        message: chrome.i18n.getMessage('initialization_message'),
        iconUrl: chrome.extension.getURL('logo_password_alert.png'),
        buttons: [{
          title: chrome.i18n.getMessage('sign_in')
        }]
      };
      chrome.notifications.create(passwordalert.background.NOTIFICATION_ID_,
          options, function() {});
      var openLoginPage_ = function(notificationId) {
        if (notificationId === passwordalert.background.NOTIFICATION_ID_) {
          loginURLs.forEach(function(url) {
            console.log('Opening ' + url);
            chrome.tabs.create({'url': url});
          });
        }
      };
      // If a user clicks on the non-button area of the notification,
      // they should still have the chance to go the login page to
      // initialize their password.
      chrome.notifications.onClicked.addListener(openLoginPage_);
      chrome.notifications.onButtonClicked.addListener(openLoginPage_);
    }
  });
};


/**
 * Prompts the user to initialize their password.
 * @private
 */
passwordalert.background.initializePasswordIfReady_ = function() {
  if (!passwordalert.background.isNewInstall_ ||
      !passwordalert.background.isInitialized_) {
    return;
  }
  var needsInit = Object.keys(passwordalert.background.SITES_).some(
      function(siteName) {
        var site = passwordalert.background.SITES_[siteName];
        if (site.shouldInitializePassword) {
          return true;
        }
      });

  if (!needsInit) {
    return;
  }

  // For OS X, we add a delay that will give the user a chance to dismiss
  // the webstore's post-install popup.  Otherwise, there will be an overlap
  // between this popup and the chrome.notification message.
  // TODO(henryc): Find a more robust way to overcome this overlap issue.
  if (navigator.appVersion.indexOf('Macintosh') != -1) {
    setTimeout(
        passwordalert.background.displayInitializePasswordNotification_,
        5000);  // 5 seconds
  } else {
    passwordalert.background.displayInitializePasswordNotification_();
  }

  setTimeout(function() {
    if (!localStorage.hasOwnProperty(passwordalert.background.SALT_KEY_)) {
      console.log('Password still has not been initialized.  ' +
                  'Start the password initialization process again.');
      passwordalert.background.initializePasswordIfReady_();
    }
  }, 300000);  // 5 minutes
};


/**
 * Complete page initialization.  This is executed after managed policy values
 * have been set.
 * @private
 */
passwordalert.background.completePageInitialization_ = function() {
  passwordalert.background.isInitialized_ = true;
  // initializePassword_ should occur after injectContentScriptIntoAllTabs_.
  // This way, the content script will be ready to receive
  // post-password initialization messages.
  passwordalert.background.injectContentScriptIntoAllTabs_(
      passwordalert.background.initializePasswordIfReady_);

  passwordalert.background.refreshPasswordLengths_();
  chrome.runtime.onMessage.addListener(
      passwordalert.background.handleRequest_);

  // Get the username from a signed in Chrome profile, which might be used
  // for reporting phishing sites (if the password store isn't initialized).
  chrome.identity.getProfileUserInfo(function(userInfo) {
    if (userInfo) {
      passwordalert.background.signed_in_email_ = userInfo.email;
    }
  });
};


/**
 * Called when the extension loads.
 * @private
 */
passwordalert.background.initializePage_ = function() {
  passwordalert.background.setManagedPolicyValuesIntoConfigurableVariables_(
      passwordalert.background.completePageInitialization_);
};


/**
 * Receives requests from content_script.js and calls the appropriate function.
 * @param {passwordalert.background.Request_} request Request message from the
 *     content_script.
 * @param {{tab: {id: number}}} sender Who sent this message.
 * @param {function(*)} sendResponse Callback with a response.
 * @private
 */
passwordalert.background.handleRequest_ = function(
    request, sender, sendResponse) {
  if (sender.tab === undefined) {
    return;
  }
  console.log(request);
  switch (request.action) {
    case 'handleKeypress':
      passwordalert.background.handleKeypress_(sender.tab.id, request);
      break;
    case 'handleKeydown':
      passwordalert.background.handleKeydown_(sender.tab.id, request);
      break;
    case 'checkString':
      passwordalert.background.checkPassword_(sender.tab.id, request,
          passwordalert.background.stateKeydown_);
      break;
    case 'statusRequest':
      passwordalert.background.pushToTab_(sender.tab.id);
      var state = {
        passwordLengths: passwordalert.background.passwordLengths_
      };
      sendResponse(JSON.stringify(state));  // Needed for pre-loaded pages.
      break;
    case 'possiblePhish':
      passwordalert.background.sendReportPage_(request);
      passwordalert.background.injectPhishingWarningIfNeeded_(
          sender.tab.id, request);
      break;
    case 'deletePossiblePassword':
      delete passwordalert.background.possiblePassword_[sender.tab.id];
      break;
    case 'setPossiblePassword':
      passwordalert.background.setPossiblePassword_(sender.tab.id, request);
      break;
    case 'savePossiblePassword':
      passwordalert.background.savePossiblePassword_(sender.tab.id, request);
      break;
    case 'getEmail':
      sendResponse(
          passwordalert.background.possiblePassword_[sender.tab.id]['email']);
      break;
  }
};


/**
 * Clears OTP mode.
 * @param {passwordalert.background.State_} state State of keydown or keypress.
 * @private
 */
passwordalert.background.clearOtpMode_ = function(state) {
  state['otpMode'] = false;
  state['otpCount'] = 0;
  state['otpTime'] = null;
  state['hash'] = '';
  if (typeof state['typed'] == 'string') {
    state['typed'] = '';
  } else {  // keydown.Typed object
    state['typed'].clear();
  }
};


/**
 * Called on each key down. Checks the most recent possible characters.
 * @param {number} tabId Id of the browser tab.
 * @param {passwordalert.background.Request_} request Request object from
 *     content_script. Contains url and referer.
 * @param {passwordalert.background.State_} state State of keypress or keydown.
 * @private
 */
passwordalert.background.checkOtp_ = function(tabId, request, state) {
  if (state['otpMode']) {
    var now = new Date();
    if (now - state['otpTime'] >
        passwordalert.background.SECONDS_TO_CLEAR_OTP_ * 1000) {
      passwordalert.background.clearOtpMode_(state);
    } else if (request.keyCode >= 0x30 && request.keyCode <= 0x39) {
      // is a digit
      state['otpCount']++;
    } else if (request.keyCode > 0x20 ||
        // non-digit printable characters reset it
        // Non-printable only allowed at start:
        state['otpCount'] > 0) {
      passwordalert.background.clearOtpMode_(state);
    }
    if (state['otpCount'] >=
        passwordalert.background.OTP_LENGTH_) {
      var item = JSON.parse(localStorage[state.hash]);
      console.log('OTP TYPED! ' + request.url);
      passwordalert.background.sendReportPassword_(
          request, item['email'], item['date'], true);
      passwordalert.background.clearOtpMode_(state);
    }
  }
};


/**
 * Called on each key down. Checks the most recent possible characters.
 * @param {number} tabId Id of the browser tab.
 * @param {passwordalert.background.Request_} request Request object from
 *     content_script. Contains url and referer.
 * @param {passwordalert.background.State_} state State of keydown or keypress.
 * @private
 */
passwordalert.background.checkAllPasswords_ = function(tabId, request, state) {
  if (state['typed'].length >= passwordalert.background.MINIMUM_PASSWORD_) {
    for (var i = 1; i < passwordalert.background.passwordLengths_.length; i++) {
      // Perform a check on every length, even if we don't have enough
      // typed characters, to avoid timing attacks.
      if (passwordalert.background.passwordLengths_[i]) {
        request.password = state['typed'].substr(-1 * i);
        passwordalert.background.checkPassword_(tabId, request, state);
      }
    }
  }
};


/**
 * Called on each key down. Checks the most recent possible characters.
 * @param {number} tabId Id of the browser tab.
 * @param {passwordalert.background.Request_} request Request object from
 *     content_script. Contains url and referer.
 * @private
 */
passwordalert.background.handleKeydown_ = function(tabId, request) {
  var state = passwordalert.background.stateKeydown_;
  passwordalert.background.checkOtp_(tabId, request, state);

  if (request.keyCode == passwordalert.background.ENTER_ASCII_CODE_) {
    state['typed'].clear();
    return;
  }

  var typedTime = new Date(request.typedTimeStamp);
  if (typedTime - state['typedTime'] >
      passwordalert.background.SECONDS_TO_CLEAR_ * 1000) {
    state['typed'].clear();
  }

  state['typed'].event(request.keyCode, request.shiftKey);
  state['typedTime'] = typedTime;

  state['typed'].trim(passwordalert.background.passwordLengths_.length);

  passwordalert.background.checkAllPasswords_(tabId, request, state);
};


/**
 * Called on each key press. Checks the most recent possible characters.
 * @param {number} tabId Id of the browser tab.
 * @param {passwordalert.background.Request_} request Request object from
 *     content_script. Contains url and referer.
 * @private
 */
passwordalert.background.handleKeypress_ = function(tabId, request) {
  var state = passwordalert.background.stateKeypress_;
  passwordalert.background.checkOtp_(tabId, request, state);

  if (request.keyCode == passwordalert.background.ENTER_ASCII_CODE_) {
    state['typed'] = '';
    return;
  }

  var typedTime = new Date(request.typedTimeStamp);
  if (typedTime - state['typedTime'] >
      passwordalert.background.SECONDS_TO_CLEAR_ * 1000) {
    state['typed'] = '';
  }

  // We're treating keyCode and charCode the same here intentionally.
  state['typed'] += String.fromCharCode(request.keyCode);
  state['typedTime'] = typedTime;

  // trim the buffer when it's too big
  if (state['typed'].length >
      passwordalert.background.passwordLengths_.length) {
    state['typed'] = state['typed'].slice(
        -1 * passwordalert.background.passwordLengths_.length);
  }

  // Send keypress event to keydown state so the keydown library can attempt
  // to guess the state of capslock.
  passwordalert.background.stateKeydown_['typed'].keypress(request.keyCode);

  // Do not check passwords if keydown is in OTP mode to avoid double-warning.
  if (!passwordalert.background.stateKeydown_['otpMode']) {
    passwordalert.background.checkAllPasswords_(tabId, request, state);
  }
};


/**
 * When password entered into a login page, temporarily save it here.
 * We do not yet know if the password is correct.
 * @param {number} tabId The tab that was used to log in.
 * @param {passwordalert.background.Request_} request Request object
 *     containing email address and password.
 * @private
 */
passwordalert.background.setPossiblePassword_ = function(tabId, request) {
  if (!request.email || !request.password) {
    return;
  }
  var site = passwordalert.background.SITES_[request.site];
  if (request.password.length < site.minimumLength) {
    console.log('password length is shorter than the minimum of ' +
        site.minimumLength);
    return;
  }

  console.log('Setting possible password for %s, password length of %s',
              request.email, request.password.length);
  var salt = passwordalert.background.generateSalt_();
  passwordalert.background.possiblePassword_[tabId] = {
    'site': request.site,
    'email': request.email,
    'password': passwordalert.background.hashPassword_(request.password, salt),
    'salt': salt,
    'length': request.password.length
  };
};


/**
 *
 * @param {number} index Index in to the localStorage array.
 * @return {*} The item.
 * @private
 */
passwordalert.background.getLocalStorageItem_ = function(index) {
  var item;
  if (localStorage.key(index) == passwordalert.background.SALT_KEY_) {
    item = null;
  } else {
    item = JSON.parse(localStorage[localStorage.key(index)]);
  }
  return item;
};


/**
 * The login was successful, so write the possible password to localStorage.
 * @param {number} tabId The tab that was used to log in.
 * @param {passwordalert.background.Request_} request Request that was passed.
 * @private
 */
passwordalert.background.savePossiblePassword_ = function(tabId, request) {
  var possiblePassword_ = passwordalert.background.possiblePassword_[tabId];
  if (!possiblePassword_) {
    return;
  }
  var email = possiblePassword_['email'];
  var password = possiblePassword_['password'];
  var length = possiblePassword_['length'];
  var site = request.site;
  var salt = possiblePassword_['salt'];

  var toStore = {};
  toStore[password] = {
    salt: salt,
    email: email,
    site: site,
    length: length,
    date: new Date()
  };

  // Clear out old password entries.
  chrome.storage.local.get(null, function(hashes) {
    Object.keys(hashes).forEach(function(hash) {
      if (hash === passwordalert.background.ALLOWED_HOSTS_KEY_) return;
      var storedSite = hashes[hash];
      if (storedSite.site === site) {
        chrome.storage.local.remove(hash);
      }
    });
  });

  console.log('Saving password for: ' + email);
  chrome.storage.local.set(toStore, function() {
    if (chrome.runtime.lastError) {
      console.log('Password for ' + email + ' failed to save!');
    }
    else {
      passwordalert.background.SITES_.initialized = true;
      console.log('Password for ' + email + ' saved.');
      if (passwordalert.background.isNewInstall_) {
        if (passwordalert.background.isEnterpriseUse_ &&
            !passwordalert.background.SITES_[site].shouldInitializePassword) {
          // If enterprise policy says not to prompt, then don't prompt.
          passwordalert.background.isNewInstall_ = false;
        } else {
          var options = {
            type: 'basic',
            title: chrome.i18n.getMessage('extension_name'),
            message: chrome.i18n.getMessage('initialization_thank_you_message'),
            iconUrl: chrome.extension.getURL('logo_password_alert.png')
          };
          chrome.notifications.create('thank_you_notification',
              options, function() {
                passwordalert.background.isNewInstall_ = false;
              });
        }
      }
      delete passwordalert.background.possiblePassword_[tabId];
      passwordalert.background.refreshPasswordLengths_();
    }
  });
};


/**
 * Updates the value of passwordalert.background.passwordLengths_ and pushes
 * new value to all content_script tabs.
 * @private
 */
passwordalert.background.refreshPasswordLengths_ = function() {
  passwordalert.background.passwordLengths_ = [];
  chrome.storage.local.get(null, function(hashes) {
    Object.keys(hashes).forEach(function(hash) {
      if (hash === passwordalert.background.ALLOWED_HOSTS_KEY_) return;
      var site = hashes[hash];
      passwordalert.background.passwordLengths_[site.length] = true;
      passwordalert.background.MINIMUM_PASSWORD_ = Math.min(
          passwordalert.background.MINIMUM_PASSWORD_,
          site.length);
    });
  });
  passwordalert.background.pushToAllTabs_();
};


/**
 * If function is called too quickly, returns false.
 * @return {boolean} Whether we are below the maximum rate.
 * @private
 */
passwordalert.background.checkRateLimit_ = function() {
  var now = new Date();
  if (!passwordalert.background.rateLimitResetDate_ ||  // initialization case
      now >= passwordalert.background.rateLimitResetDate_) {
    // setHours() handles wrapping correctly.
    passwordalert.background.rateLimitResetDate_ =
        now.setHours(now.getHours() + 1);
    passwordalert.background.rateLimitCount_ = 0;
  }

  passwordalert.background.rateLimitCount_++;

  return passwordalert.background.rateLimitCount_ <=
      passwordalert.background.MAX_RATE_PER_HOUR_;
};


/**
 * Determines if a password has been typed and if so creates alert. Also used
 * for sending OTP alerts.
 * @param {number} tabId The tab that sent this message.
 * @param {passwordalert.background.Request_} request Request object from
 *     content_script.
 * @param {passwordalert.background.State_} state State of keypress or keydown.
 * @private
 */
passwordalert.background.checkPassword_ = function(tabId, request, state) {
  if (!passwordalert.background.checkRateLimit_()) {
    return;  // This limits content_script brute-forcing the password.
  }
  if (state['otpMode']) {
    return;  // If password was recently typed, then no need to check again.
  }
  if (!request.password) {
    return;
  }

  // todo: implement site ignores
  var testString = request.password;
  chrome.storage.local.get(null, function(hashes) {
    Object.keys(hashes).some(function(hash) {
      if (hash === passwordalert.background.ALLOWED_HOSTS_KEY_) return;
      var item = hashes[hash];
      var salt = item.salt;
      var testHash = passwordalert.background.hashPassword_(testString, salt);
      if (hash === testHash) {
        console.log('PASSWORD TYPED! ' + request.url);

        if (passwordalert.background.SITES_[item.site]['reportURL']) {
          passwordalert.background.sendReportPassword_(
              request, item['email'], item['date'], false);
        }

        console.log('Password has been typed.');
        state['hash'] = hash;
        state['otpCount'] = 0;
        state['otpMode'] = true;
        state['otpTime'] = new Date();

        passwordalert.background.injectPasswordWarningIfNeeded_(
            request.url, item.site, tabId);

        return true;
      }
    });
  });
};


/**
 * Check if the password warning banner should be injected and inject it.
 * @param {string|undefined} url URI that triggered this warning.
 * @param {string} siteName Site name that triggered this warning.
 * @param {number} tabId The tab that sent this message.
 *
 * @private
 */
passwordalert.background.injectPasswordWarningIfNeeded_ =
    function(url, siteName, tabId) {
  if (passwordalert.background.enterpriseMode_ &&
      !passwordalert.background.displayUserAlert_) {
    return;
  }

  // todo: per-site host settings
  chrome.storage.local.get(
      passwordalert.background.ALLOWED_HOSTS_KEY_,
      function(result) {
        var toParse = document.createElement('a');
        toParse.href = url;
        var currentHost = toParse.origin;
        var allowedHosts = result[passwordalert.background.ALLOWED_HOSTS_KEY_];
        if (allowedHosts != undefined && allowedHosts[currentHost]) {
          return;
        }
        // TODO(adhintz) Change to named parameters.
        var warning_url = chrome.extension.getURL('password_warning.html') +
            '?' + encodeURIComponent(currentHost) +
            '&' + encodeURIComponent(siteName) +
            '&' + tabId;
        chrome.tabs.create({'url': warning_url});
      });

};


/**
 * Check if the phishing warning should be injected and inject it.
 * TODO(henryc): Rename "inject" to something more accurate, maybe "display".
 * @param {number} tabId The tab that sent this message.
 * @param {passwordalert.background.Request_} request Request message from the
 *     content_script.
 * @private
 */
passwordalert.background.injectPhishingWarningIfNeeded_ = function(
    tabId, request) {
  chrome.storage.local.get(request.site, function(site) {
    var toParse = document.createElement('a');
    toParse.href = request.url;
    var currentHost = toParse.origin;
    var phishingWarningWhitelist = site['phishing_warning_whitelist'];
    if (typeof phishingWarningWhitelist !== 'undefined' &&
        phishingWarningWhitelist[currentHost]) {
      return;
    }

    // TODO(adhintz) Change to named parameters.
    var warning_url = chrome.extension.getURL('phishing_warning.html') +
        '?' + tabId +
        '&' + encodeURIComponent(request.url || '') +
        '&' + encodeURIComponent(currentHost) +
        '&' + encodeURIComponent(site.securityEmailAddress);
    chrome.tabs.update({'url': warning_url});
  });
};


/**
 * Sends a password typed alert to the server.
 * @param {passwordalert.background.Request_} request Request object from
 *     content_script. Contains url and referer.
 * @param {string} email The email to report.
 * @param {string} date The date when the correct password hash was saved.
 *                      It is a string from JavaScript's Date().
 * @param {boolean} otp True if this is for an OTP alert.
 * @private
 */
passwordalert.background.sendReportPassword_ = function(
    request, email, date, otp) {
  passwordalert.background.sendReport_(
      request,
      date,
      otp,
      'password/');
};


/**
 * Sends a phishing page alert to the server.
 * @param {passwordalert.background.Request_} request Request object from
 *     content_script. Contains url and referer.
 * @private
 */
passwordalert.background.sendReportPage_ = function(request) {
  passwordalert.background.sendReport_(
      request,
      '',  // date not used.
      false, // not an OTP alert.
      'page/');
};


/**
 * Sends an alert to the server if in Enterprise mode.
 * @param {passwordalert.background.Request_} request Request object from
 *     content_script. Contains url and referer.
 * @param {string} date The date when the correct password hash was saved.
 *                      It is a string from JavaScript's Date().
 * @param {boolean} otp True if this is for an OTP alert.
 * @param {string} path Server path for report, such as "page/" or "password/".
 * @private
 */
passwordalert.background.sendReport_ = function(
    request, date, otp, path) {
  if (!passwordalert.background.enterpriseMode_) {
    console.log('Not in enterprise mode, so not sending a report.');
    return;
  }

  chrome.storage.local.get(request.site, function(site) {
    // no report URL defined
    if (!site.reportURL) {
      console.log('No report URL provided');
      return;
    }
    var xhr = new XMLHttpRequest();
    xhr.open('POST', site.reportURL + path, true);
    xhr.onreadystatechange = function() {};

    // this header is specifically for Google
    xhr.setRequestHeader('X-Same-Domain', 'true');
    xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');

    // Turn 'example.com,1.example.com' into 'example.com'
    var domain = site.emailDomain.split(',')[0];
    domain = domain.trim();

    var data = (
        'email=' + encodeURIComponent(email) +
        '&domain=' + encodeURIComponent(domain) +
        '&referer=' + encodeURIComponent(request.referer || '') +
        '&url=' + encodeURIComponent(request.url || '') +
        '&version=' + chrome.runtime.getManifest().version
        );
    if (date) {
      // password_date is in seconds. Date.parse() returns milliseconds.
      data += '&password_date=' + Math.floor(Date.parse(date) / 1000);
    }
    if (otp) {
      data += '&otp=true';
    }
    // todo: address dead (?) phishing code here
    if (request.looksLikeGoogle) {
      data += '&looksLikeGoogle=true';
    }
    chrome.identity.getAuthToken({'interactive': false}, function(oauthToken) {
      if (oauthToken) {
        console.log('Successfully retrieved oauth token.');
        data += '&oauth_token=' + encodeURIComponent(oauthToken);
      }
      console.log('Sending alert to the server.');
      xhr.send(data);
    });
  });

};


/**
 * Guesses the email address for the current user.
 * @param {string} siteName Website corresponding to user
 * @return {string|undefined} email address for this user or undefined.
 * @private
 */
passwordalert.background.guessUser_ = function(siteName) {
  chrome.storage.local.get(siteName, function(site) {
    return site.email;
  });
};


/**
 * Calculates salted, partial hash of the password.
 * Throws an error if none is passed in.
 * @param {string} password The password to hash.
 * @param {string} salt The password salt.
 * @return {string} Hash as a string of hex characters.
 * @private
 */
passwordalert.background.hashPassword_ = function(password, salt) {
  var sha1 = new goog.crypt.Sha1();
  sha1.update(salt);
  sha1.update(goog.crypt.stringToUtf8ByteArray(password));
  var hash = sha1.digest();

  // Only keep HASH_BITS_ number of bits of the hash.
  var bits = passwordalert.background.HASH_BITS_;
  for (var i = 0; i < hash.length; i++) {
    if (bits >= 8) {
      bits -= 8;
    } else if (bits == 0) {
      hash[i] = 0;
    } else { // 1 to 7 bits
      var mask = 0xffffff00; // Used to shift in 1s into the low byte.
      mask = mask >> bits;
      hash[i] = hash[i] & mask; // hash[i] is only 8 bits.
      bits = 0;
    }
  }

  // Do not return zeros at the end that were bit-masked out.
  return goog.crypt.byteArrayToHex(hash).substr(0,
      Math.ceil(passwordalert.background.HASH_BITS_ / 4));
};


/**
 * Generates and saves a salt if needed.
 * @return {string} Salt for the hash.
 * @private
 */
passwordalert.background.generateSalt_ = function() {
  // Generate a salt and save it.
  var salt = new Uint32Array(1);
  window.crypto.getRandomValues(salt);
  return salt[0].toString();
};


/**
 * Posts status message to all tabs.
 * @private
 */
passwordalert.background.pushToAllTabs_ = function() {
  chrome.tabs.query({}, function(tabs) {
    for (var i = 0; i < tabs.length; i++) {
      passwordalert.background.pushToTab_(tabs[i].id);
    }
  });
};


/**
 * Sends a message with the tab's state to the content_script on a tab.
 * @param {number} tabId Tab to receive the message.
 * @private
 */
passwordalert.background.pushToTab_ = function(tabId) {
  var state = {
    passwordLengths: passwordalert.background.passwordLengths_
  };
  chrome.tabs.sendMessage(tabId, JSON.stringify(state));
};


// Set this early, or else the install event will not be picked up.
chrome.runtime.onInstalled.addListener(
    passwordalert.background.handleNewInstall_);

// Set listener before initializePage_ which calls chrome.storage.managed.get.
chrome.storage.onChanged.addListener(
    passwordalert.background.handleManagedPolicyChanges_);

passwordalert.background.initializePage_();
