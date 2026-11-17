const $ = id => document.getElementById(id);

let csrfToken = "";
let currentUser = null;

async function refreshCsrf() {
  const response = await fetch("/api/csrf-token", {
    credentials: "same-origin"
  });

  if (!response.ok) throw new Error("Security initialization failed.");

  const data = await response.json();
  csrfToken = data.csrfToken;
}

async function api(url, options = {}) {
  const method = options.method || "GET";

  const headers = {
    ...(options.headers || {})
  };

  if (options.body) {
    headers["Content-Type"] = "application/json";
  }

  if (!["GET", "HEAD", "OPTIONS"].includes(method)) {
    headers["x-csrf-token"] = csrfToken;
  }

  const response = await fetch(url, {
    ...options,
    method,
    headers,
    credentials: "same-origin"
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(data.error || "Request failed.");
  }

  return data;
}

function show(id) {
  $(id).classList.remove("hidden");
}

function hide(id) {
  $(id).classList.add("hidden");
}

function result(id, message) {
  $(id).textContent = message;
}

function formData(form) {
  return Object.fromEntries(new FormData(form).entries());
}

function showAccount(type) {
  show("account");
  hide("registerForm");
  hide("loginForm");

  if (type === "register") {
    show("registerForm");
    $("accountTitle").textContent = "Create Account";
  } else {
    show("loginForm");
    $("accountTitle").textContent = "Login";
  }

  $("account").scrollIntoView({ behavior: "smooth" });
}

$("loginNav").addEventListener("click", () => {
  showAccount("login");
});

$("registerNav").addEventListener("click", () => {
  showAccount("register");
});

$("registerForm").addEventListener("submit", async event => {
  event.preventDefault();

  try {
    const data = await api("/api/register", {
      method: "POST",
      body: JSON.stringify(formData(event.target))
    });

    currentUser = data.user;
    await refreshCsrf();
    event.target.reset();
    result("accountResult", "Account created successfully.");
    await loadUser();
  } catch (error) {
    result("accountResult", error.message);
  }
});

$("loginForm").addEventListener("submit", async event => {
  event.preventDefault();

  try {
    const data = await api("/api/login", {
      method: "POST",
      body: JSON.stringify(formData(event.target))
    });

    currentUser = data.user;
    await refreshCsrf();
    event.target.reset();
    result("accountResult", "Login successful.");
    await loadUser();
  } catch (error) {
    result("accountResult", error.message);
  }
});

$("logoutBtn").addEventListener("click", async () => {
  try {
    await api("/api/logout", {
      method: "POST"
    });

    currentUser = null;
    await refreshCsrf();
    await loadUser();
  } catch (error) {
    alert(error.message);
  }
});

$("contactForm").addEventListener("submit", async event => {
  event.preventDefault();

  try {
    const data = await api("/api/contact", {
      method: "POST",
      body: JSON.stringify(formData(event.target))
    });

    result("contactResult", data.message);
    event.target.reset();
  } catch (error) {
    result("contactResult", error.message);
  }
});

function cell(row, value) {
  const td = document.createElement("td");
  td.textContent = value == null ? "" : String(value);
  row.appendChild(td);
}

function renderTable(container, headings, rows) {
  const table = document.createElement("table");
  const head = document.createElement("tr");

  headings.forEach(heading => {
    cell(head, heading);
  });

  const thead = document.createElement("thead");
  thead.appendChild(head);
  table.appendChild(thead);

  const tbody = document.createElement("tbody");

  rows.forEach(values => {
    const row = document.createElement("tr");
    values.forEach(value => cell(row, value));
    tbody.appendChild(row);
  });

  table.appendChild(tbody);
  $(container).replaceChildren(table);
}

async function loadAdmin() {
  const stats = await api("/api/admin/stats");

  $("totalUsers").textContent = stats.users;
  $("totalMessages").textContent = stats.messages;
  $("newMessages").textContent = stats.new_messages;

  const users = await api("/api/admin/users");

  renderTable("usersList",
    ["ID", "Name", "Email", "Role", "Created"],
    users.map(u => [
      u.id, u.name, u.email, u.role,
      new Date(u.created_at).toLocaleString()
    ])
  );

  const messages = await api("/api/admin/messages");

  const messageBox = $("messagesList");
  messageBox.replaceChildren();

  const table = document.createElement("table");
  const header = document.createElement("tr");

  ["ID", "Name", "Email", "Subject",
   "Message", "Status", "Action"].forEach(h => cell(header, h));

  const thead = document.createElement("thead");
  thead.appendChild(header);
  table.appendChild(thead);

  const tbody = document.createElement("tbody");

  messages.forEach(m => {
    const row = document.createElement("tr");

    [m.id, m.name, m.email, m.subject,
     m.message, m.status].forEach(v => cell(row, v));

    const td = document.createElement("td");
    const select = document.createElement("select");

    ["new", "read", "closed"].forEach(status => {
      const option = document.createElement("option");
      option.value = status;
      option.textContent = status;
      option.selected = m.status === status;
      select.appendChild(option);
    });

    const button = document.createElement("button");
    button.textContent = "Save";

    button.addEventListener("click", async () => {
      try {
        await api("/api/admin/messages/" +
          encodeURIComponent(m.id), {
            method: "PATCH",
            body: JSON.stringify({ status: select.value })
          });

        await loadAdmin();
      } catch (error) {
        alert(error.message);
      }
    });

    td.append(select, button);
    row.appendChild(td);
    tbody.appendChild(row);
  });

  table.appendChild(tbody);
  messageBox.appendChild(table);
}

async function loadUser() {
  hide("adminPanel");
  hide("userPanel");
  hide("account");
  hide("loginNav");
  hide("registerNav");
  show("logoutBtn");

  try {
    const data = await api("/api/me");
    currentUser = data.user;

    if (!currentUser) {
      show("loginNav");
      show("registerNav");
      hide("logoutBtn");
      return;
    }

    if (currentUser.role === "admin") {
      show("adminPanel");
      await loadAdmin();
    } else {
      show("userPanel");
      $("welcome").textContent =
        "Welcome, " + currentUser.name + "!";
    }
  } catch (error) {
    currentUser = null;
    show("loginNav");
    show("registerNav");
    hide("logoutBtn");
  }
}

async function initialize() {
  try {
    await refreshCsrf();
    await loadUser();
  } catch (error) {
    console.error(error);
    alert("Website initialization failed. Please reload.");
  }
}

initialize();
