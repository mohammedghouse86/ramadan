// data.js
// ---------------------------------------------------------------------------
// Lightweight in-memory "database". No external DB — everything lives here.
// NOTE: auto-created users and the audit log are in-memory only and reset
// when the server restarts. The seeded tenants/users below always exist.
// ---------------------------------------------------------------------------
const crypto = require('crypto');

// ===== Shared Ramadan reference content (tenant-agnostic) ===================
const ramadan = {
  month: "Ramadan",
  number: 9,
  description:
    "Ramadan is the ninth month of the Islamic calendar, observed by Muslims worldwide as a month of fasting, prayer, reflection, and community.",
  benefits: [
    "Spiritual growth",
    "Increased charity",
    "Better self-discipline",
    "Improved health",
  ],
  fasting:
    "Muslims fast from dawn (Suhoor) until sunset (Iftar), refraining from food, drink, and other physical needs.",
  iftar:
    "Iftar is the meal eaten by Muslims to break their fast at sunset. It typically begins with dates and water.",
  suhoor:
    "Suhoor is the pre-dawn meal before the fast begins. It is recommended to eat something nourishing before Fajr (dawn) prayer.",
  prayers:
    "Taraweeh prayers are special night prayers performed during Ramadan after the Isha prayer. They are highly recommended and often performed in congregation.",
  tips: [
    "Stay hydrated during non-fasting hours",
    "Eat a balanced Suhoor and Iftar",
    "Avoid over-eating",
    "Get enough rest",
  ],
  zakat:
    "Zakat is a form of almsgiving treated in Islam as a religious obligation. During Ramadan, many Muslims choose to give Zakat to maximize rewards.",
};

// ===== Tenants =============================================================
// Each tenant is an isolated organization. Integer ids only.
const tenants = [
  {
    id: 1,
    name: "Crescent Org",
    timezone: "Asia/Riyadh",
    // Tenant-scoped Iftar timetable — admin1 / user1 see these.
    iftarTimes: {
      Mecca: "6:45 PM",
      Medina: "6:40 PM",
      Cairo: "6:30 PM",
    },
    zakatNisab: 3960, // local nisab threshold used by /ramadan/zakat_due
    // Admin-only sensitive config
    contactEmail: "ops@crescent.example.com",
    apiKey: "tnt_1_9f3a7c21bd44",
  },
  {
    id: 2,
    name: "Hilal Foundation",
    timezone: "Asia/Karachi",
    // admin2 sees these instead.
    iftarTimes: {
      Hyderabad: "6:43 PM",
      Karachi: "6:55 PM",
      Lahore: "7:02 PM",
    },
    zakatNisab: 4200,
    contactEmail: "ops@hilal.example.com",
    apiKey: "tnt_2_5e88b0fa9912",
  },
];

// ===== Users ===============================================================
// Integer ids only. role is "admin" or "user". pii holds personal data.
const users = [
  {
    id: crypto.randomUUID(),
    name: "admin1",
    role: "admin",
    tenantId: 1,
    pii: {
      fullName: "Aisha Rahman",
      email: "aisha.rahman@crescent.example.com",
      phone: "+966-50-111-2233",
      address: "12 King Fahd Rd, Riyadh, Saudi Arabia",
      dateOfBirth: "1985-03-14",
      nationalId: "1098765432",
    },
  },
  {
    id: crypto.randomUUID(),
    name: "user1",
    role: "user",
    tenantId: 1,
    pii: {
      fullName: "Bilal Khan",
      email: "bilal.khan@crescent.example.com",
      phone: "+966-55-444-5566",
      address: "88 Olaya St, Riyadh, Saudi Arabia",
      dateOfBirth: "1994-09-02",
      nationalId: "1076543210",
    },
  },
  {
    id: crypto.randomUUID(),
    name: "admin2",
    role: "admin",
    tenantId: 2,
    pii: {
      fullName: "Fatima Siddiqui",
      email: "fatima.siddiqui@hilal.example.com",
      phone: "+92-300-777-8899",
      address: "5 Gulberg III, Lahore, Pakistan",
      dateOfBirth: "1989-12-21",
      nationalId: "35202-1234567-8",
    },
  },
];

// ===== Audit log (in-memory) ===============================================
const auditLog = []; // { id, tenantId, actorId, actorName, action, at }
let nextAuditId = 1;

// ===========================================================================
//  Helpers
// ===========================================================================

function getTenant(tenantId) {
  return tenants.find((t) => t.id === tenantId) || null;
}

function findUserByName(name) {
  if (!name) return null;
  const lower = String(name).toLowerCase();
  return users.find((u) => u.name.toLowerCase() === lower) || null;
}

function findUserById(id) {
  return users.find((u) => u.id === id) || null;
}

function listUsersByTenant(tenantId) {
  return users.filter((u) => u.tenantId === tenantId);
}

// Creates a new regular user. Used when someone logs in with an unknown name.
function createUser({ name, role = "user", tenantId = 1, pii = {} }) {
  const user = {
    id: crypto.randomUUID(),
    name,
    role: role === "admin" ? "admin" : "user",
    tenantId,
    pii: {
      fullName: pii.fullName || name,
      email: pii.email || null,
      phone: pii.phone || null,
      address: pii.address || null,
      dateOfBirth: pii.dateOfBirth || null,
      nationalId: pii.nationalId || null,
    },
  };
  users.push(user);
  return user;
}

function deleteUser(id) {
  const idx = users.findIndex((u) => u.id === id);
  if (idx === -1) return false;
  users.splice(idx, 1);
  return true;
}

// Returns a safe view of a user WITHOUT PII (for general/non-admin responses).
function publicUser(user) {
  if (!user) return null;
  return {
    id: user.id,
    name: user.name,
    role: user.role,
    tenantId: user.tenantId,
  };
}

function addAuditEntry({ tenantId, actorId, actorName, action }) {
  const entry = {
    id: nextAuditId++,
    tenantId,
    actorId,
    actorName,
    action,
    at: new Date().toISOString(),
  };
  auditLog.push(entry);
  return entry;
}

function listAuditByTenant(tenantId) {
  return auditLog.filter((e) => e.tenantId === tenantId);
}

module.exports = {
  ramadan,
  tenants,
  users,
  auditLog,
  getTenant,
  findUserByName,
  findUserById,
  listUsersByTenant,
  createUser,
  deleteUser,
  publicUser,
  addAuditEntry,
  listAuditByTenant,
};
