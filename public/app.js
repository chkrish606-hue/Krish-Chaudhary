/* =========================================
   KP PANEL SHOP
   AUTHENTICATION FRONTEND
========================================= */


/* =========================================
   ELEMENTS
========================================= */

const loginPage =
  document.getElementById("loginPage");

const registerPage =
  document.getElementById("registerPage");

const openRegister =
  document.getElementById("openRegister");

const openLogin =
  document.getElementById("openLogin");

const loginForm =
  document.getElementById("loginForm");

const registerForm =
  document.getElementById("registerForm");

const loginMessage =
  document.getElementById("loginMessage");

const registerMessage =
  document.getElementById("registerMessage");

const googleLogin =
  document.getElementById("googleLogin");

const googleRegister =
  document.getElementById("googleRegister");

const toastElement =
  document.getElementById("toast");


/* =========================================
   PAGE SWITCH
========================================= */

function showLoginPage() {

  loginPage.classList.remove("hidden");

  registerPage.classList.add("hidden");

  clearMessages();

}


function showRegisterPage() {

  loginPage.classList.add("hidden");

  registerPage.classList.remove("hidden");

  clearMessages();

}


openRegister.addEventListener(
  "click",
  showRegisterPage
);


openLogin.addEventListener(
  "click",
  showLoginPage
);


/* =========================================
   MESSAGES
========================================= */

function clearMessages() {

  loginMessage.textContent = "";

  registerMessage.textContent = "";

  loginMessage.className = "message";

  registerMessage.className = "message";

}


function showMessage(
  element,
  text,
  type = ""
) {

  element.textContent = text;

  element.className =
    "message " + type;

}


/* =========================================
   TOAST
========================================= */

function showToast(text) {

  toastElement.textContent = text;

  toastElement.classList.add("show");

  setTimeout(() => {

    toastElement.classList.remove("show");

  }, 2300);

}


/* =========================================
   PASSWORD SHOW / HIDE
========================================= */

const passwordButtons =
  document.querySelectorAll(
    ".password-toggle"
  );


passwordButtons.forEach(button => {

  button.addEventListener(
    "click",
    function () {

      const targetId =
        this.getAttribute("data-target");

      const passwordInput =
        document.getElementById(targetId);


      if (
        passwordInput.type ===
        "password"
      ) {

        passwordInput.type =
          "text";

        this.textContent = "🙈";

      } else {

        passwordInput.type =
          "password";

        this.textContent = "👁";

      }

    }
  );

});


/* =========================================
   LOCAL STORAGE USERS
========================================= */

function getUsers() {

  try {

    const users =
      localStorage.getItem(
        "kp_panel_users"
      );

    if (!users) {

      return [];

    }

    return JSON.parse(users);

  } catch (error) {

    console.error(error);

    return [];

  }

}


function saveUsers(users) {

  localStorage.setItem(
    "kp_panel_users",
    JSON.stringify(users)
  );

}


/* =========================================
   REGISTER
========================================= */

registerForm.addEventListener(
  "submit",
  function (event) {

    event.preventDefault();


    const username =
      document
        .getElementById("registerUsername")
        .value
        .trim();


    const email =
      document
        .getElementById("registerEmail")
        .value
        .trim()
        .toLowerCase();


    const password =
      document
        .getElementById("registerPassword")
        .value;


    /* Username validation */

    if (username.length < 3) {

      showMessage(
        registerMessage,
        "Username must contain at least 3 characters.",
        "error"
      );

      return;

    }


    /* Username characters */

    const usernamePattern =
      /^[a-zA-Z0-9_.-]+$/;


    if (
      !usernamePattern.test(username)
    ) {

      showMessage(
        registerMessage,
        "Username can only use letters, numbers, _ . and -",
        "error"
      );

      return;

    }


    /* Email validation */

    if (
      email &&
      !isValidEmail(email)
    ) {

      showMessage(
        registerMessage,
        "Please enter a valid email address.",
        "error"
      );

      return;

    }


    /* Password validation */

    if (password.length < 6) {

      showMessage(
        registerMessage,
        "Password must contain at least 6 characters.",
        "error"
      );

      return;

    }


    /* Get users */

    const users =
      getUsers();


    /* Check username */

    const usernameExists =
      users.some(
        user =>
          user.username.toLowerCase() ===
          username.toLowerCase()
      );


    if (usernameExists) {

      showMessage(
        registerMessage,
        "This username already exists.",
        "error"
      );

      return;

    }


    /* Check email */

    if (email) {

      const emailExists =
        users.some(
          user =>
            user.email &&
            user.email === email
        );


      if (emailExists) {

        showMessage(
          registerMessage,
          "This email is already registered.",
          "error"
        );

        return;

      }

    }


    /* Create account */

    const newUser = {

      id:
        Date.now().toString(),

      username:
        username,

      email:
        email,

      password:
        password,

      createdAt:
        new Date().toISOString()

    };


    users.push(newUser);


    saveUsers(users);


    /* Clear form */

    registerForm.reset();


    showMessage(
      registerMessage,
      "Account created successfully. You can sign in now.",
      "success"
    );


    showToast(
      "Account created successfully"
    );


    /* Go login after small delay */

    setTimeout(() => {

      showLoginPage();

      document
        .getElementById("loginUsername")
        .value = username;

    }, 1000);

  }
);


/* =========================================
   LOGIN
========================================= */

loginForm.addEventListener(
  "submit",
  function (event) {

    event.preventDefault();


    const identifier =
      document
        .getElementById("loginUsername")
        .value
        .trim()
        .toLowerCase();


    const password =
      document
        .getElementById("loginPassword")
        .value;


    if (!identifier) {

      showMessage(
        loginMessage,
        "Please enter your username or email.",
        "error"
      );

      return;

    }


    if (!password) {

      showMessage(
        loginMessage,
        "Please enter your password.",
        "error"
      );

      return;

    }


    const users =
      getUsers();


    const user =
      users.find(
        currentUser => {

          const usernameMatch =
            currentUser.username &&
            currentUser.username.toLowerCase() ===
            identifier;


          const emailMatch =
            currentUser.email &&
            currentUser.email.toLowerCase() ===
            identifier;


          return (
            (usernameMatch ||
              emailMatch) &&
            currentUser.password ===
              password
          );

        }
      );


    if (!user) {

      showMessage(
        loginMessage,
        "Invalid username/email or password.",
        "error"
      );

      return;

    }


    /* Save current session */

    const session = {

      id:
        user.id,

      username:
        user.username,

      email:
        user.email || "",

      loginTime:
        new Date().toISOString()

    };


    localStorage.setItem(
      "kp_panel_current_user",
      JSON.stringify(session)
    );


    showMessage(
      loginMessage,
      "Login successful. Welcome " +
        user.username +
        "!",
      "success"
    );


    showToast(
      "Signed in successfully"
    );


    /*
      Yahan aap apne dashboard ka URL
      laga sakte ho.

      Example:

      window.location.href =
        "dashboard.html";
    */

  }
);


/* =========================================
   GOOGLE LOGIN
========================================= */

googleLogin.addEventListener(
  "click",
  function () {

    startGoogleLogin(
      loginMessage
    );

  }
);


googleRegister.addEventListener(
  "click",
  function () {

    startGoogleLogin(
      registerMessage
    );

  }
);


function startGoogleLogin(
  messageElement
) {

  /*
    REAL GOOGLE LOGIN ke liye Firebase
    ya kisi OAuth provider ko connect
    karna zaroori hai.

    Abhi button properly clickable hai
    aur configuration message show karega.
  */

  showMessage(
    messageElement,
    "Google login is ready to connect. Add Firebase Google Authentication configuration.",
    "error"
  );


  showToast(
    "Google authentication needs configuration"
  );

}


/* =========================================
   EMAIL VALIDATION
========================================= */

function isValidEmail(email) {

  const pattern =
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

  return pattern.test(email);

}


/* =========================================
   ENTER KEY / FORM UX
========================================= */

document
  .querySelectorAll("input")
  .forEach(input => {

    input.addEventListener(
      "input",
      function () {

        loginMessage.textContent = "";

        registerMessage.textContent = "";

      }
    );

  });


/* =========================================
   CHECK EXISTING SESSION
========================================= */

function checkSession() {

  try {

    const session =
      localStorage.getItem(
        "kp_panel_current_user"
      );


    if (session) {

      const user =
        JSON.parse(session);

      console.log(
        "Current user:",
        user
      );

    }

  } catch (error) {

    console.error(error);

  }

}


checkSession();
