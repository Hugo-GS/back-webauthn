========================
CODE SNIPPETS
========================
TITLE: Installing Project Dependencies with Deno
DESCRIPTION: This command installs all necessary project dependencies using Deno's built-in package management. It should be executed after cloning the repository to prepare the development environment.

SOURCE: https://github.com/masterkale/simplewebauthn/blob/master/README.md#_snippet_0

LANGUAGE: Shell
CODE:
```
deno install
```

----------------------------------------

TITLE: Importing SimpleWebAuthnBrowser Functions - JavaScript
DESCRIPTION: Imports the `browserSupportsWebAuthn` and `startRegistration` functions from the `SimpleWebAuthnBrowser` library, which are essential for initiating WebAuthn operations in the browser.

SOURCE: https://github.com/masterkale/simplewebauthn/blob/master/example/public/index.html#_snippet_1

LANGUAGE: JavaScript
CODE:
```
const { browserSupportsWebAuthn, startRegistration } = SimpleWebAuthnBrowser;
```

----------------------------------------

TITLE: Installing @simplewebauthn/server with npm
DESCRIPTION: This command installs the @simplewebauthn/server package using npm, making it available for Node.js projects. It is intended for Node LTS 20.x and higher, providing server-side WebAuthn utilities.

SOURCE: https://github.com/masterkale/simplewebauthn/blob/master/packages/server/README.md#_snippet_0

LANGUAGE: sh
CODE:
```
npm install @simplewebauthn/server
```

----------------------------------------

TITLE: Installing @simplewebauthn/server with Deno
DESCRIPTION: This command adds the @simplewebauthn/server package from JSR using Deno, making it available for Deno projects. It is suitable for Deno v1.43 and higher, offering server-side WebAuthn functionalities.

SOURCE: https://github.com/masterkale/simplewebauthn/blob/master/packages/server/README.md#_snippet_1

LANGUAGE: sh
CODE:
```
deno add jsr:@simplewebauthn/server
```

----------------------------------------

TITLE: Handling WebAuthn Registration Flow - JavaScript
DESCRIPTION: Attaches an event listener to the registration button to initiate the WebAuthn registration process. It fetches options from the server, calls `startRegistration`, and sends the attestation response back to the server for verification, updating the UI with success or error messages.

SOURCE: https://github.com/masterkale/simplewebauthn/blob/master/example/public/index.html#_snippet_6

LANGUAGE: JavaScript
CODE:
```
document.querySelector('#btnRegBegin').addEventListener('click', async () => {
  const elemSuccess = document.querySelector('#regSuccess');
  const elemError = document.querySelector('#regError');
  const elemDebug = document.querySelector('#regDebug');

  // Reset success/error messages
  elemSuccess.innerHTML = '';
  elemError.innerHTML = '';
  elemDebug.innerHTML = '';

  const resp = await fetch('/generate-registration-options');
  let attResp;

  try {
    const opts = await resp.json();
    printDebug(elemDebug, 'Registration Options', JSON.stringify(opts, null, 2));
    hideAuthForm();
    attResp = await startRegistration({ optionsJSON: opts });
    printDebug(elemDebug, 'Registration Response', JSON.stringify(attResp, null, 2));
  } catch (error) {
    if (error.name === 'InvalidStateError') {
      elemError.innerText = 'Error: Authenticator was probably already registered by user';
    } else {
      elemError.innerText = error;
    }
    throw error;
  }

  const verificationResp = await fetch('/verify-registration', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(attResp),
  });

  const verificationJSON = await verificationResp.json();
  printDebug(elemDebug, 'Server Response', JSON.stringify(verificationJSON, null, 2));

  if (verificationJSON && verificationJSON.verified) {
    elemSuccess.innerHTML = `Authenticator registered!`;
  } else {
    elemError.innerHTML = `Oh no, something went wrong! Response: <pre>${JSON.stringify(
      verificationJSON,
    )}</pre>`;
  }
});
```

----------------------------------------

TITLE: Installing SimpleWebAuthn Server via Deno Add Command
DESCRIPTION: This snippet provides the shell command to install the `@simplewebauthn/server` package from JSR using `deno add`. This command is applicable for Deno versions 1.43 and higher, simplifying package management.

SOURCE: https://github.com/masterkale/simplewebauthn/blob/master/deno/README.md#_snippet_2

LANGUAGE: Shell
CODE:
```
# Deno v1.43 and higher
deno add jsr:@simplewebauthn/server
```

----------------------------------------

TITLE: Installing @simplewebauthn/browser with NPM
DESCRIPTION: This command installs the `@simplewebauthn/browser` package using npm, the Node.js package manager. It is intended for projects using Node.js LTS 20.x and higher, making the library available for import in your JavaScript or TypeScript files.

SOURCE: https://github.com/masterkale/simplewebauthn/blob/master/packages/browser/README.md#_snippet_0

LANGUAGE: sh
CODE:
```
npm install @simplewebauthn/browser
```

----------------------------------------

TITLE: Logging Debug Content to HTML Element - JavaScript
DESCRIPTION: Appends formatted debug messages to a specified HTML element, ensuring each new message starts on a new line and includes a descriptive title for clarity.

SOURCE: https://github.com/masterkale/simplewebauthn/blob/master/example/public/index.html#_snippet_3

LANGUAGE: JavaScript
CODE:
```
function printDebug(elemDebug, title, output) { if (elemDebug.innerHTML !== '') { elemDebug.innerHTML += '\n'; } elemDebug.innerHTML += `// ${title}\n`; elemDebug.innerHTML += `${output}\n`; }
```

----------------------------------------

TITLE: Installing @simplewebauthn/browser with Deno
DESCRIPTION: This command adds the `@simplewebauthn/browser` package to a Deno project from JSR. It is suitable for Deno v1.43 and higher, allowing the library to be imported and used within Deno applications.

SOURCE: https://github.com/masterkale/simplewebauthn/blob/master/packages/browser/README.md#_snippet_1

LANGUAGE: sh
CODE:
```
deno add jsr:@simplewebauthn/browser
```

----------------------------------------

TITLE: Handling WebAuthn Authentication Flow - JavaScript
DESCRIPTION: Attaches an event listener to the authentication button to initiate the WebAuthn authentication process. It fetches options from the server, calls `startAuthentication`, and sends the assertion response back to the server for verification, updating the UI with success or error messages.

SOURCE: https://github.com/masterkale/simplewebauthn/blob/master/example/public/index.html#_snippet_7

LANGUAGE: JavaScript
CODE:
```
document.querySelector('#btnAuthBegin').addEventListener('click', async () => {
  const elemSuccess = document.querySelector('#authSuccess');
  const elemError = document.querySelector('#authError');
  const elemDebug = document.querySelector('#authDebug');

  // Reset success/error messages
  elemSuccess.innerHTML = '';
  elemError.innerHTML = '';
  elemDebug.innerHTML = '';

  const resp = await fetch('/generate-authentication-options');
  let asseResp;

  try {
    const opts = await resp.json();
    printDebug(elemDebug, 'Authentication Options', JSON.stringify(opts, null, 2));
    hideAuthForm();
    asseResp = await startAuthentication({ optionsJSON: opts });
    printDebug(elemDebug, 'Authentication Response', JSON.stringify(asseResp, null, 2));
  } catch (error) {
    elemError.innerText = error;
    throw new Error(error);
  }

  const verificationResp = await fetch('/verify-authentication', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(asseResp),
  });

  const verificationJSON = await verificationResp.json();
  printDebug(elemDebug, 'Server Response', JSON.stringify(verificationJSON, null, 2));

  if (verificationJSON && verificationJSON.verified) {
    elemSuccess.innerHTML = `User authenticated!`;
  } else {
    elemError.innerHTML = `Oh no, something went wrong! Response: <pre>${JSON.stringify(
      verificationJSON,
    )}</pre>`;
  }
});
```

----------------------------------------

TITLE: Determining Packages for Release
DESCRIPTION: This Deno task command helps identify which packages within the monorepo have changes that necessitate a new version release. The output of this command guides which packages require entries in the 'CHANGELOG.md' file.

SOURCE: https://github.com/masterkale/simplewebauthn/blob/master/HANDBOOK.md#_snippet_1

LANGUAGE: Shell
CODE:
```
deno task version
```

----------------------------------------

TITLE: Running Server Package Tests in Watch Mode (Deno)
DESCRIPTION: This command navigates into the 'packages/server' directory and starts the unit tests for the server-side WebAuthn library in watch mode using Deno's task runner. This mode automatically re-runs tests whenever relevant source files are modified, aiding rapid development.

SOURCE: https://github.com/masterkale/simplewebauthn/blob/master/README.md#_snippet_4

LANGUAGE: Shell
CODE:
```
cd packages/server/ && deno task test:watch
```

----------------------------------------

TITLE: Authenticating User with SimpleWebAuthn and Conditional UI (JavaScript)
DESCRIPTION: This snippet demonstrates how to initiate WebAuthn authentication using SimpleWebAuthnBrowser.startAuthentication with Conditional UI and autofill. It fetches authentication options from the server, processes the WebAuthn response, and verifies it, updating the UI based on the outcome. It highlights a known Chrome race condition and provides debugging output via an assumed 'printDebug' utility.

SOURCE: https://github.com/masterkale/simplewebauthn/blob/master/example/public/index.html#_snippet_0

LANGUAGE: javascript
CODE:
```
const { startAuthentication } = SimpleWebAuthnBrowser; /** * Conditional UI test * * 1. Start Chrome Canary 105+ with the requisite Conditional UI flag: * * open -a /Applications/Google\ Chrome\ Canary.app --args --enable-features=WebAuthenticationConditionalUI * * 2. Create an entry in chrome://settings/passwords (temporary requirement) e.g.: * * - Site: https://example.simplewebauthn.dev/ * - Username: user@example.simplewebauthn.dev * - Password: whatever * * 3. Register a credential * * 4. Reload the page * * 5. Interact with the username field above the Authenticate button * * Notes: * * I'm currently trying to get to calling WebAuthn as fast as I can here, there's a * Chrome race condition with autofill that sometimes prevents a credential from appearing. * * See: https://bugs.chromium.org/p/chromium/issues/detail?id=1322967&q=component%3ABlink%3EWebAuthentication&can=2 * * I've been assured this race condition is temporary, at which point we'll probably be able * to include this just before </body> as we'd typically do. And at that point we can * probably use async/await as well for more sane-looking code. */ fetch('/generate-authentication-options')
 .then(resp => resp.json())
 .then(opts => {
 console.log('Authentication Options (Autofill)', opts);
 startAuthentication({ optionsJSON: opts, useAutofill: true })
 .then(async asseResp => {
 // We can assume the DOM has loaded by now because it had to for the user to be able
 // to interact with an input to choose a credential from the autofill
 const elemSuccess = document.querySelector('#authSuccess');
 const elemError = document.querySelector('#authError');
 const elemDebug = document.querySelector('#authDebug');
 printDebug(
 elemDebug, 'Authentication Response (Autofill)', JSON.stringify(asseResp, null, 2),
 );
 const verificationResp = await fetch('/verify-authentication', {
 method: 'POST',
 headers: {
 'Content-Type': 'application/json',
 },
 body: JSON.stringify(asseResp),
 });
 const verificationJSON = await verificationResp.json();
 printDebug(
 elemDebug, 'Server Response (Autofill)', JSON.stringify(verificationJSON, null, 2),
 );
 if (verificationJSON && verificationJSON.verified) {
 elemSuccess.innerHTML = `User authenticated!`;
 } else {
 elemError.innerHTML = `Oh no, something went wrong! Response: <pre>${JSON.stringify(
 verificationJSON,
 )}</pre>`;
 }
 })
 .catch(err => {
 console.error('(Autofill)', err);
 });
 });
```

----------------------------------------

TITLE: Running Browser Package Tests in Watch Mode (Deno)
DESCRIPTION: This command navigates into the 'packages/browser' directory and starts the unit tests for the browser-side WebAuthn library in watch mode using Deno's task runner. This mode automatically re-runs tests whenever relevant source files are modified, aiding rapid development.

SOURCE: https://github.com/masterkale/simplewebauthn/blob/master/README.md#_snippet_3

LANGUAGE: Shell
CODE:
```
cd packages/browser/ && deno task test:watch
```

----------------------------------------

TITLE: Preventing Default Event Submission - JavaScript
DESCRIPTION: A utility function designed to prevent the default action of an event, commonly used to stop form submissions or link navigations from reloading the page.

SOURCE: https://github.com/masterkale/simplewebauthn/blob/master/example/public/index.html#_snippet_2

LANGUAGE: JavaScript
CODE:
```
function stopSubmit(event) { event.preventDefault(); }
```

----------------------------------------

TITLE: Checking Browser WebAuthn Support - JavaScript
DESCRIPTION: Checks if the user's browser supports WebAuthn. If not, it hides the authentication controls and displays an error message, otherwise it proceeds to define UI helper functions.

SOURCE: https://github.com/masterkale/simplewebauthn/blob/master/example/public/index.html#_snippet_4

LANGUAGE: JavaScript
CODE:
```
if (!browserSupportsWebAuthn()) {
  document.querySelector('.controls').style.display = 'none';
  document.querySelector('.systemError').innerText = "It seems this browser doesn't support WebAuthn...";
} else {
  function hideAuthForm() {
    document.getElementById('inputUsername').style.display = 'none';
  }
}
```

----------------------------------------

TITLE: Direct Import for SimpleWebAuthn Server After Deno Add
DESCRIPTION: This snippet illustrates the direct import statement for `generateAuthenticationOptions` from the `@simplewebauthn/server` package after it has been installed using `deno add`. This import style is concise and relies on Deno's module resolution.

SOURCE: https://github.com/masterkale/simplewebauthn/blob/master/deno/README.md#_snippet_3

LANGUAGE: TypeScript
CODE:
```
import { generateAuthenticationOptions } from '@simplewebauthn/server';
```

----------------------------------------

TITLE: Hiding Authentication Input Form - JavaScript
DESCRIPTION: A helper function that sets the display style of the HTML element with the ID 'inputUsername' to 'none', effectively hiding the username input field from the user interface.

SOURCE: https://github.com/masterkale/simplewebauthn/blob/master/example/public/index.html#_snippet_5

LANGUAGE: JavaScript
CODE:
```
function hideAuthForm() {
  document.getElementById('inputUsername').style.display = 'none';
}
```

----------------------------------------

TITLE: Publishing @simplewebauthn/server Package
DESCRIPTION: This command, executed from the monorepo root, builds and publishes the '@simplewebauthn/server' package. It pushes the package to both NPM and JSR, and should be run after updating its version in 'deno.json' and adding 'CHANGELOG.md' entries.

SOURCE: https://github.com/masterkale/simplewebauthn/blob/master/HANDBOOK.md#_snippet_3

LANGUAGE: Shell
CODE:
```
deno task publish:server
```

----------------------------------------

TITLE: Publishing @simplewebauthn/browser Package
DESCRIPTION: This command, executed from the monorepo root, builds and publishes the '@simplewebauthn/browser' package. It pushes the package to both NPM and JSR, and should be run after updating its version in 'deno.json' and adding 'CHANGELOG.md' entries.

SOURCE: https://github.com/masterkale/simplewebauthn/blob/master/HANDBOOK.md#_snippet_2

LANGUAGE: Shell
CODE:
```
deno task publish:browser
```

----------------------------------------

TITLE: Running Server Package Unit Tests (Deno)
DESCRIPTION: This command navigates into the 'packages/server' directory and executes the unit tests specifically for the server-side WebAuthn library using Deno's task runner. It's used to verify the functionality and correctness of the server package.

SOURCE: https://github.com/masterkale/simplewebauthn/blob/master/README.md#_snippet_2

LANGUAGE: Shell
CODE:
```
cd packages/server/ && deno task test
```

----------------------------------------

TITLE: Running Browser Package Unit Tests (Deno)
DESCRIPTION: This command navigates into the 'packages/browser' directory and executes the unit tests specifically for the browser-side WebAuthn library using Deno's task runner. It's used to verify the functionality and correctness of the browser package.

SOURCE: https://github.com/masterkale/simplewebauthn/blob/master/README.md#_snippet_1

LANGUAGE: Shell
CODE:
```
cd packages/browser/ && deno task test
```

----------------------------------------

TITLE: Recommended JSR Import for SimpleWebAuthn Server in Deno
DESCRIPTION: This snippet shows the recommended way to import `generateAuthenticationOptions` from the SimpleWebAuthn server package using Deno's native JSR import syntax. This is the preferred method after the deprecation of `deno.land/x` imports.

SOURCE: https://github.com/masterkale/simplewebauthn/blob/master/deno/README.md#_snippet_1

LANGUAGE: TypeScript
CODE:
```
import { generateAuthenticationOptions } from 'jsr:@simplewebauthn/server';
```

----------------------------------------

TITLE: Deprecated Import for SimpleWebAuthn Server in Deno (deno.land/x)
DESCRIPTION: This snippet demonstrates the old, now deprecated, method of importing `generateAuthenticationOptions` from the SimpleWebAuthn server package using a `deno.land/x` URL. This approach is no longer supported and should be migrated to JSR imports.

SOURCE: https://github.com/masterkale/simplewebauthn/blob/master/deno/README.md#_snippet_0

LANGUAGE: TypeScript
CODE:
```
import { generateAuthenticationOptions } from 'https://deno.land/x/simplewebauthn/deno/server.ts';
```

----------------------------------------

TITLE: Including @simplewebauthn/browser UMD ES2021 Bundle
DESCRIPTION: This HTML script tag includes the ES2021 UMD bundle of `@simplewebauthn/browser` directly into a web page. This version is optimized for modern browsers and makes the library's methods available globally under the `SimpleWebAuthnBrowser` object.

SOURCE: https://github.com/masterkale/simplewebauthn/blob/master/packages/browser/README.md#_snippet_2

LANGUAGE: html
CODE:
```
<script src="https://unpkg.com/@simplewebauthn/browser/dist/bundle/index.umd.min.js"></script>
```

----------------------------------------

TITLE: Including @simplewebauthn/browser UMD ES5 Bundle
DESCRIPTION: This HTML script tag includes the ES5 UMD bundle of `@simplewebauthn/browser` directly into a web page. This version includes polyfills for older browsers like IE11 and Edge Legacy, enabling WebAuthn feature detection in those environments, and makes the library available globally as `SimpleWebAuthnBrowser`.

SOURCE: https://github.com/masterkale/simplewebauthn/blob/master/packages/browser/README.md#_snippet_3

LANGUAGE: html
CODE:
```
<script src="https://unpkg.com/@simplewebauthn/browser/dist/bundle/index.es5.umd.min.js"></script>
```

----------------------------------------

TITLE: Updating Deno DOM Types
DESCRIPTION: This command navigates into the 'packages/types' directory and executes a Deno task to extract and update DOM types. This step is crucial after updating Deno to a newer version to ensure type compatibility and should be committed.

SOURCE: https://github.com/masterkale/simplewebauthn/blob/master/HANDBOOK.md#_snippet_0

LANGUAGE: Shell
CODE:
```
(cd packages/types; deno task extract-dom-types)
```

----------------------------------------

TITLE: Running Codegen Task for SimpleWebAuthn Types (Shell)
DESCRIPTION: This shell command executes the codegen task, which is responsible for copying the TypeScript typings from the @simplewebauthn/types package into the @simplewebauthn/browser and @simplewebauthn/server packages. It should be run whenever changes are made to the typings to ensure consistency across related packages.

SOURCE: https://github.com/masterkale/simplewebauthn/blob/master/packages/types/README.md#_snippet_0

LANGUAGE: sh
CODE:
```
deno task codegen
```