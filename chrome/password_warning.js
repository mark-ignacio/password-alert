/**
 * @license
 * Copyright 2015 Google Inc. All Rights Reserved.
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
 * @fileoverview Warning displayed on a password alert.
 * @author adhintz@google.com (Drew Hintz)
 */

goog.provide('passwordalert.warning');
goog.require('passwordalert');

// URI encoded parameters from the URL. [currentHost, email, tabId]
var parameters = window.location.search.substr(1).split('&');
var siteName = decodeURIComponent(parameters[1]);

document.getElementById('warning_banner_header').textContent =
    chrome.i18n.getMessage('password_warning_banner_header');
document.getElementById('warning_banner_text').textContent =
    chrome.i18n.getMessage('password_warning_banner_body');
document.getElementById('learn_more').textContent =
    chrome.i18n.getMessage('learn_more');

document.getElementById('reset').textContent =
    chrome.i18n.getMessage('reset_password');
document.getElementById('ignore').textContent =
    chrome.i18n.getMessage('ignore');
document.getElementById('always_ignore').textContent =
    chrome.i18n.getMessage('always_ignore');


document.getElementById('reset').onclick = function() {
  var site = passwordalert.SITES[siteName];
  window.location.href = site.changePasswordURL;
};


document.getElementById('ignore').onclick = function() {
  chrome.tabs.get(parseInt(parameters[2]), function(tab) {
    chrome.tabs.highlight({'tabs': tab.index}, function() {});
    window.close();
  });
};


ALLOWED_HOSTS_KEY_ = 'allowed_hosts';


/**
 * Save the allowed host into chrome storage.  The saved object
 * in chrome storage has the below structure. The top-level key is the salted
 * partial hash given to StorageArea get(), and the associated value will be
 * an inner object that has all the host details.
 *
 * {partialHash: {
 *     ...
 *     site: 'Facebook',
 *     alwaysIgnore: {
 *        https://www.example1.com: true,
 *        'https://www.example2.com:8080': true
 *     },
 *     ...
 * }
 *
 * @private
 */
document.getElementById('always_ignore').onclick = function() {
  if (confirm(chrome.i18n.getMessage('always_ignore_confirmation'))) {
    chrome.storage.local.get(null, function(hashes) {
      var currentHost = decodeURIComponent(parameters[0]);
      for (var hash in hashes) {
        if (!hashes.hasOwnProperty(hash)) continue;
        var site = hashes[hash];
        if (site.site === siteName) {
          site.alwaysIgnore[currentHost] = true;
          var data = {};
          data[hash] = site;
          chrome.storage.local.set(data);
          window.close();
        }
      }
    });
  }
};
