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
 * @fileoverview Receives keyboard events and sends keyboard events to
 * background.js via sendMessage.
 * @author adhintz@google.com (Drew Hintz)
 * @author mignacio@fb.com (Mark Ignacio)
 */

'use strict';

goog.provide('passwordalert');

// These requires must also be added to content_script_test.html
goog.require('goog.format.EmailAddress');
goog.require('goog.string');
goog.require('goog.uri.utils');


/**
 * Object that holds configurations for specified websites.
 * @public {object}
 * @type {{siteName: {loginURL: RegExp, loginFormSelector: string,
 *                    loginEmailSelector: string, secondFactorURL: RegExp,
 *                    secondFactorFormSelector: string,
 *                    changePasswordURL: string,
 *                    changePasswordFormSelector: string,
 *                    changePasswordName: string,
 *                    securityEmailAddress: (string|undefined)}
 *       }}
 */
passwordalert.SITES = {
  Facebook: {
    loginURL: /^https:\/\/[a-z\-]+\.facebook\.com(\/|\/login\.php)?$/,
    loginFormSelector: '#login_form',
    loginEmailSelector: 'input[name=email]',
    secondFactorURL: /^https:\/\/[a-z\-]+\.facebook\.com\/checkpoint\/?$/,
    secondFactorFormSelector: 'form.checkpoint',
    changePasswordURL: 'https://www.facebook.com/settings?' +
    'tab=account&section=password&view',
    changePasswordFormSelector: 'form[action="/ajax/settings/account/password.php"]',
    changePasswordName: 'password_new',
    securityEmailAddress: 'cert@fb.com'
  }
};


/**
 * Namespace for chrome's managed storage.
 * @private {string}
 * @const
 */
passwordalert.MANAGED_STORAGE_NAMESPACE_ = 'managed';

/**
 * The URL for the current page.
 * @private {string}
 */
passwordalert.url_ = location.href.toString();


/**
 * If Password Alert is running on the current page.
 * @private {boolean}
 */
passwordalert.isRunning_ = false;


/**
 * The timeStamp from the most recent keypress event.
 * @private {number}
 */
passwordalert.lastKeypressTimeStamp_;


/**
 * The timeStamp from the most recent keydown event.
 * @private {number}
 */
passwordalert.lastKeydownTimeStamp_;


/**
 * Password lengths for passwords that are being watched.
 * If an array offset is true, then that password length is watched.
 * Value comes from background.js.
 * @private {Array.<boolean>}
 */
passwordalert.passwordLengths_;


/**
 * Is password alert used in enterprise environment.  If false, then it's
 * used by individual consumer.
 * @private {boolean}
 */
passwordalert.isEnterpriseUse_ = false;


/**
 * Indicates that the managed policy has been set. Required to complete init.
 * @private {boolean}
 */
passwordalert.policyLoaded_ = false;


/**
 * Indicates the DOM has been loaded. Required to complete initialization.
 * @private {boolean}
 */
passwordalert.domContentLoaded_ = false;


/**
 * Key for the allowed hosts object in chrome storage.
 * @private {string}
 * @const
 */
passwordalert.ALLOWED_HOSTS_KEY_ = 'allowed_hosts';


/**
 * Set the managed policy values into the configurable variables.
 * @param {function()} callback Executed after policy values have been set.
 * @private
 */
passwordalert.setManagedPolicyValuesIntoConfigurableVariables_ =
  function (callback) {
    chrome.storage.managed.get(function (managedPolicy) {
      if (Object.keys(managedPolicy).length == 0) {
        passwordalert.isEnterpriseUse_ = false;
      } else {
        // nb: overwrites existing policies
        managedPolicy.forEach(function (managedSite) {
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
          passwordalert.SITES[policyName] = managedSite;
        });
      }
      callback();
    });
};


// This switch style is a bit verbose with lots of properties. Perhaps it
// would be cleaner to have a list of allowed properties and do something like
// if (changedPolicy in listOfPolicies)
//   passwordalert[changedPolicy + '_'] = newPolicyValue;
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
passwordalert.handleManagedPolicyChanges_ =
    function(changedPolicies, storageNamespace) {
      if (storageNamespace ==
          passwordalert.MANAGED_STORAGE_NAMESPACE_) {
        console.log('Handling changed policies.');
        Object.keys(changedPolicies).forEach(function (changedPolicy) {
          if (!passwordalert.isEnterpriseUse_) {
            passwordalert.isEnterpriseUse_ = true;
            console.log('Enterprise use enabled via updated managed policy.');
          }

          passwordalert.SITES[changedPolicy] =
              changedPolicies[changedPolicy]['newValue'];
        });
      }
    };

/**
 * Checks only up to the path of a URL against a regexp or string.
 * @param {string} url
 * @param {string|RegExp} toMatch
 * @return bool
 */
passwordalert.pathMatch = function (url, toMatch) {
  var questionIndex = url.indexOf('?');
  if (questionIndex != -1) {
    url = url.slice(0, questionIndex);
  }
  if (toMatch instanceof RegExp) {
    return toMatch.test(url);
  }
  else if (typeof toMatch === 'string') {
    return toMatch === url;
  }
};


/**
 * Complete page initialization.  This is executed after managed policy values
 * have been set.
 *
 * Save or delete any existing passwords. Listen for form submissions on
 * corporate login pages.
 * @private
 */
passwordalert.completePageInitializationIfReady_ = function() {
  // match page against each site's login pages

  var url;
  var qIndex = passwordalert.url_.indexOf('?');
  if (qIndex === -1) {
    url = passwordalert.url_;
  }
  else {
    url = passwordalert.url_.slice(0, qIndex);
  }

  Object.keys(passwordalert.SITES_).forEach(function (name) {
    var site = passwordalert.SITES_[name];
    console.log('Checking for site: ' + name);
    if (passwordalert.pathMatch(url, site.changePasswordURL)
        && document.querySelector(site.changePasswordFormSelector)) {
      console.log('Password change page detected: ' + passwordalert.url_);

      // Logging into FB is possible with var email = any email or phone
      // number, so let's just get whatever was entered in the first place.
      chrome.runtime.sendMessage({site: name, action: 'getEmail'},
          function (email) {
            if (!email) return;

            var form = document.querySelector(
                site.changePasswordFormSelector);
            form.addEventListener('submit', function () {
              chrome.runtime.sendMessage({
                action: 'setPossiblePassword',
                site: name,
                email: email,
                password: form[site.changePasswordName]
              });
            });
          }
      );
    }
    else if (passwordalert.pathMatch(url, site.secondFactorURL)) {
      console.log('Second factor URL detected: ' + passwordalert.url_);

      // Password was typed in successfully if we're on the 2FA page.
      chrome.runtime.sendMessage({
        action: 'savePossiblePassword',
        site: name
      });
    }
    else if (passwordalert.pathMatch(url, site.loginURL)
        && document.querySelector(site.loginFormSelector)) {
      var loginForm = document.querySelector(site.loginFormSelector);
      console.log('Login page detected: ' + passwordalert.url_);

      loginForm.addEventListener('submit',
          passwordalert.saveGaiaPassword_
      );
    }
    else {
      // todo: port phishing detection from upstream
      chrome.runtime.sendMessage({
        action: 'savePossiblePassword',
        site: name
      });
    }
  });

  chrome.runtime.onMessage.addListener(
      /**
       * @param {string} msg JSON object containing valid password lengths.
       */
      function(msg) {
        passwordalert.stop_();
        passwordalert.start_(msg);
      });
  chrome.runtime.sendMessage({action: 'statusRequest'});
};


/**
 * Sets variables to enable watching for passwords being typed. Called when
 * a message from the options_subscriber arrives.
 * @param {string} msg JSON object containing password lengths and OTP mode.
 * @private
 */
passwordalert.start_ = function(msg) {
  var state = JSON.parse(msg);

  if (state.passwordLengths) {
    // TODO(henryc): Content_script is now only using passwordLengths_ to tell
    // if passwordLengths_length == 0. So, do not store passwordLengths,
    // just have the message from background page tell it to start or stop.
    passwordalert.passwordLengths_ = state.passwordLengths;
    if (passwordalert.passwordLengths_.length === 0) {
      passwordalert.stop_(); // no passwords, so no need to watch
      return;
    }
  }

  Object.keys(passwordalert.SITES).forEach(function(name) {
    var site = passwordalert.SITES[name];

    // todo: make "always ignore" whitelist a page if not disabled for site
    if ((passwordalert.pathMatch(passwordalert.url_, site.loginURL)
          && document.querySelector(site.loginFormSelector))
        || passwordalert.pathMatch(passwordalert.url_, site.secondFactorURL)) {
      chrome.runtime.sendMessage({
        action: 'whitelisted',
        site: name
      });
    }
    else {
      passwordalert.isRunning_ = true;
    }
  });

  passwordalert.looksLikeGooglePage_();  // Run here so that it's cached.
};


/**
 * Disables watching on the current page.
 * @private
 */
passwordalert.stop_ = function() {
  passwordalert.isRunning_ = false;
};


/**
 * Called on each key press. Checks the most recent possible characters.
 * @param {Event} evt Key press event.
 * @private
 */
passwordalert.handleKeypress_ = function(evt) {
  if (!passwordalert.isRunning_) return;

  // Legitimate keypress events should have the view set and valid charCode.
  if (evt.view == null || evt.charCode == 0) {
    return;
  }

  // Legitimate keypress events should have increasing timeStamps.
  if (evt.timeStamp <= passwordalert.lastKeypressTimeStamp_) {
    return;
  }
  passwordalert.lastKeypressTimeStamp_ = evt.timeStamp;

  chrome.runtime.sendMessage({
    action: 'handleKeypress',
    keyCode: evt.charCode,
    typedTimeStamp: evt.timeStamp,
    url: passwordalert.url_,
    referer: document.referrer.toString(),
    looksLikeGoogle: passwordalert.looksLikeGooglePage_()
  });
};


/**
 * Called on each key down. Checks the most recent possible characters.
 * @param {Event} evt Key down event.
 * @private
 */
passwordalert.handleKeydown_ = function(evt) {
  if (!passwordalert.isRunning_) return;

  // Legitimate keypress events should have the view set and valid charCode.
  if (evt.view == null || evt.keyCode == 0) {
    return;
  }

  // Legitimate keypress events should have increasing timeStamps.
  if (evt.timeStamp <= passwordalert.lastKeydownTimeStamp_) {
    return;
  }
  passwordalert.lastKeydownTimeStamp_ = evt.timeStamp;

  chrome.runtime.sendMessage({
    action: 'handleKeydown',
    keyCode: evt.keyCode,
    shiftKey: evt.shiftKey,
    typedTimeStamp: evt.timeStamp,
    url: passwordalert.url_,
    referer: document.referrer.toString(),
    looksLikeGoogle: passwordalert.looksLikeGooglePage_()
  });
};


/**
 * Called on each paste. Checks the entire pasted string to save on cpu cycles.
 * @param {Event} evt Paste event.
 * @private
 */
passwordalert.handlePaste_ = function(evt) {
  if (!passwordalert.isRunning_) return;

  // Legitimate paste events should have the clipboardData set.
  if (evt.clipboardData === undefined) {
    return;
  }

  // Legitimate paste events should have increasing timeStamps.
  if (evt.timeStamp <= passwordalert.lastKeypressTimeStamp_) {
    return;
  }
  passwordalert.lastKeypressTimeStamp_ = evt.timeStamp;

  chrome.runtime.sendMessage({
    action: 'checkString',
    password: evt.clipboardData.getData('text/plain').trim(),
    url: passwordalert.url_,
    referer: document.referrer.toString(),
    looksLikeGoogle: passwordalert.looksLikeGooglePage_()
  });
};


/**
 * Called when SSO login page is submitted. Sends possible password to
 * background.js.
 * @param {Event} evt Form submit event that triggered this. Not used.
 * @private
 */
passwordalert.saveSsoPassword_ = function(evt) {
  console.log('Saving SSO password.');
  if (passwordalert.validateSso_()) {
    var username =
        document.querySelector(passwordalert.sso_username_selector_).value;
    var password =
        document.querySelector(passwordalert.sso_password_selector_).value;
    if (username.indexOf('@') == -1) {
      username += '@' + passwordalert.corp_email_domain_.split(',')[0].trim();
    }
    chrome.runtime.sendMessage({
      action: 'setPossiblePassword',
      email: username,
      password: password
    });
  }
};


/**
 * Called when the GAIA page is submitted. Sends possible
 * password to background.js.
 * @param {Event} evt Form submit event that triggered this. Not used.
 * @private
 */
passwordalert.saveGaiaPassword_ = function(evt) {
  console.log('Saving login password.');
  //TODO(adhintz) Should we do any validation here?
  var loginForm = evt.target;
  var email = loginForm.email ?
      goog.string.trim(loginForm.email.value.toLowerCase()) : '';
  var password = loginForm.pass ? loginForm.pass.value : '';
  if ((passwordalert.isEnterpriseUse_ &&
      !passwordalert.isEmailInDomain_(email)) ||
      goog.string.isEmptyString(goog.string.makeSafe(password))) {
    return;  // Ignore generic @gmail.com logins or for other domains.
  }
  chrome.runtime.sendMessage({
    action: 'setPossiblePassword',
    email: email,
    password: password
  });
};


/**
 * Called when GAIA password is changed. Sends possible password to
 * background.js.
 * @private
 */
passwordalert.saveChangedPassword_ = function() {
  // To ensure that only a valid password is saved, wait and see if we
  // navigate away from the change password page.  If we stay on the
  // same page, then the password is not valid and should not be saved.
  var passwordChangeStartTime = Date.now();
  window.onbeforeunload = function() {
    if ((Date.now() - passwordChangeStartTime) > 1000) {
      return;
    }
    console.log('Saving changed password.');
    var dataConfig =
        document.querySelector('div[data-config]').getAttribute('data-config');
    var start = dataConfig.indexOf('",["') + 4;
    var end = dataConfig.indexOf('"', start);
    var email = dataConfig.substring(start, end);

    if (goog.format.EmailAddress.isValidAddress(email)) {
      console.log('Parsed email on change password page is valid: %s', email);
      chrome.runtime.sendMessage({
        action: 'setPossiblePassword',
        email: email,
        password:
            document.querySelector('input[aria-label="New password"]').value
      });
      return;
    }
    console.log('Parsed email on change password page is not valid: %s', email);
  };
};


/**
 * Called when the GAIA page is submitted. Sends possible
 * password to background.js.
 * @param {string} email Email address to check.
 * @return {boolean} True if email address is for a configured corporate domain.
 * @private
 */
passwordalert.isEmailInDomain_ = function(email) {
  var domains = passwordalert.corp_email_domain_.split(',');
  for (var i in domains) {
    if (goog.string.endsWith(email, '@' + domains[i].trim())) {
      return true;
    }
  }
  return false;
};


/**
 * Checks if the sso login page is filled in.
 * @return {boolean} Whether the sso login page is filled in.
 * @private
 */
passwordalert.validateSso_ = function() {
  var username = document.querySelector(passwordalert.sso_username_selector_);
  var password = document.querySelector(passwordalert.sso_password_selector_);
  if ((username && !username.value) ||
      (password && !password.value)) {
    console.log('SSO data is not filled in.');
    return false;
  }
  console.log('SSO data is filled in.');
  return true;
};


/**
 * Detects if this page looks like a Google login page.
 * For example, a phishing page would return true.
 * Cached so it only runs once per content_script load.
 * @return {boolean} True if this page looks like a Google login page.
 * @private
 */
passwordalert.looksLikeGooglePage_ = function() {
  if (passwordalert.looks_like_google_ == true ||
      passwordalert.looks_like_google_ == false) {
    return passwordalert.looks_like_google_;
  }
  var allHtml = document.documentElement.innerHTML.slice(0, 100000);
  for (var i in passwordalert.corp_html_) {
    if (allHtml.indexOf(passwordalert.corp_html_[i]) >= 0) {
      passwordalert.looks_like_google_ = true;
      return true;
    }
  }
  passwordalert.looks_like_google_ = false;
  return false;
};


/**
 * Detects if this page looks like a Google login page, but with a more
 * strict set of rules to reduce false positives.
 * For example, a phishing page would return true.
 * @return {boolean} True if this page looks like a Google login page.
 * @private
 */
passwordalert.looksLikeGooglePageTight_ = function() {
  // Only look in the first 100,000 characters of a page to avoid
  // impacting performance for large pages. Although an attacker could use this
  // to avoid detection, they could obfuscate the HTML just as easily.
  var allHtml = document.documentElement.innerHTML.slice(0, 100000);
  for (var i in passwordalert.corp_html_tight_) {
    if (allHtml.indexOf(passwordalert.corp_html_tight_[i]) >= 0) {
      console.log('Looks like (tight) login page.');
      return true;
    }
  }
  return false;
};


/**
 * Detects if the page is whitelisted as not a phishing page or for password
 * typing.
 * @return {boolean} True if this page is whitelisted.
 * @private
 */
passwordalert.whitelistUrl_ = function() {
  var domain = goog.uri.utils.getDomain(passwordalert.url_) || '';
  for (var i in passwordalert.whitelist_top_domains_) {
    if (goog.string.endsWith(domain,
                             passwordalert.whitelist_top_domains_[i])) {
      console.log('Whitelisted domain detected: ' + domain);
      return true;
    }
  }
  return false;
};


// Listen for policy changes and then set initial managed policy:
chrome.storage.onChanged.addListener(passwordalert.handleManagedPolicyChanges_);
passwordalert.setManagedPolicyValuesIntoConfigurableVariables_(
    passwordalert.completePageInitializationIfReady_);

window.addEventListener('keypress', passwordalert.handleKeypress_, true);
window.addEventListener('keydown', passwordalert.handleKeydown_, true);
window.addEventListener('paste', function(evt) {
  passwordalert.handlePaste_(evt);
}, true);
document.addEventListener('DOMContentLoaded', function() {
  passwordalert.domContentLoaded_ = true;
  passwordalert.completePageInitializationIfReady_();
});
// Check to see if we already missed DOMContentLoaded:
if (document.readyState == 'interactive' ||
    document.readyState == 'complete' ||
    document.readyState == 'loaded') {
  passwordalert.domContentLoaded_ = true;
  passwordalert.completePageInitializationIfReady_();
}
