"use strict";
const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const ROOT = __dirname, PORT = process.env.PORT || 3000;
const DATA = path.join(ROOT, "data", "school.json");
const SECRET = process.env.SESSION_SECRET || "replace-this-development-secret-before-deploying";
const roles = { ADMIN: "administrator", TEACHER: "teacher", PARENT: "parent" };
const id = (prefix) => `${prefix}_${crypto.randomUUID()}`;
const passwordHash = (password, salt = crypto.randomBytes(16).toString("hex")) => {
  const hash = crypto.scryptSync(password, salt, 64).toString("hex"); return `${salt}:${hash}`;
};
const passwordMatches = (password, stored) => {
  const [salt, expected] = stored.split(":");
  const actual = crypto.scryptSync(password, salt, 64).toString("hex");
  return crypto.timingSafeEqual(Buffer.from(actual, "hex"), Buffer.from(expected, "hex"));
};
const sign = (value) => crypto.createHmac("sha256", SECRET).update(value).digest("base64url");
const token = (user) => { const body = Buffer.from(JSON.stringify({ id: user.id, role: user.role, exp: Date.now() + 28800000 })).toString("base64url"); return `${body}.${sign(body)}`; };
const userFromToken = (raw, db) => {
  if (!raw) return null; const [body, signature] = raw.split(".");
  if (!body || !signature || !crypto.timingSafeEqual(Buffer.from(sign(body)), Buffer.from(signature))) return null;
  try { const claims = JSON.parse(Buffer.from(body, "base64url")); return claims.exp > Date.now() ? db.users.find(u => u.id === claims.id && u.active) : null; } catch { return null; }
};
function seed() {
  return { school: { name: "My School" }, activeYearId: "year_2026", years: [{ id: "year_2026", name: "2026–27", active: true }],
    users: [{ id: "usr_admin", name: "School Administrator", email: "admin@school.local", role: roles.ADMIN, password: passwordHash("ChangeMe!2026"), active: true }],
    teachers: [], students: [], classes: [{ id: "class_1", name: "Grade 1", active: true, sections: [{ id: "sec_1a", name: "A", classTeacherId: null }] }],
    subjects: [], exams: [], announcements: [], attendance: [], audit: [] };
}
class Store {
  constructor() { fs.mkdirSync(path.dirname(DATA), { recursive: true }); if (!fs.existsSync(DATA)) fs.writeFileSync(DATA, JSON.stringify(seed(), null, 2)); this.data = JSON.parse(fs.readFileSync(DATA)); }
  save() { fs.writeFileSync(DATA, JSON.stringify(this.data, null, 2)); }
  audit(actor, action, entity, entityId, details = "") { this.data.audit.unshift({ id: id("audit"), at: new Date().toISOString(), actorId: actor.id, actor: actor.email, action, entity, entityId, details }); this.data.audit = this.data.audit.slice(0, 500); this.save(); }
}
const store = new Store();
function json(res, status, body) { res.writeHead(status, { "Content-Type": "application/json", "Cache-Control": "no-store" }); res.end(JSON.stringify(body)); }
function parseCookies(req) { return Object.fromEntries((req.headers.cookie || "").split(";").map(v => v.trim().split("=")).filter(x => x.length === 2)); }
async function body(req) { let raw = ""; for await (const chunk of req) raw += chunk; try { return JSON.parse(raw || "{}"); } catch { throw new Error("Invalid JSON"); } }
function publicUser(u) { const { password, ...safe } = u; return safe; }
function requireRole(req, res, allowed) { const user = userFromToken(parseCookies(req).session, store.data); if (!user) { json(res, 401, { error: "Authentication required" }); return null; } if (!allowed.includes(user.role)) { json(res, 403, { error: "You are not authorized for this action" }); return null; } return user; }
function nextStudentId() { const n = store.data.students.length + 1; return `STU-${new Date().getFullYear()}-${String(n).padStart(4, "0")}`; }
function dashboard() { const d = store.data, activeTeachers = d.teachers.filter(t => t.active).length; const strengths = d.classes.map(c => ({ classId: c.id, name: c.name, sections: c.sections.map(s => ({ name: s.name, students: d.students.filter(x => x.classId === c.id && x.sectionId === s.id && x.status === "active").length })) }));
  const today = new Date().toISOString().slice(0, 10), todayAttendance = d.attendance.filter(x => x.date === today); const present = todayAttendance.filter(x => x.status === "present").length;
  return { totalStudents: d.students.filter(s => s.status === "active").length, totalActiveTeachers: activeTeachers, totalClasses: d.classes.filter(c => c.active).length, totalSections: d.classes.reduce((n, c) => n + c.sections.length, 0), classStrength: strengths, attendance: { date: today, recorded: todayAttendance.length, rate: todayAttendance.length ? Math.round(present * 100 / todayAttendance.length) : null }, upcomingExams: d.exams.filter(e => e.date >= today).sort((a,b) => a.date.localeCompare(b.date)).slice(0, 5), announcements: d.announcements.slice(0, 5), activities: d.audit.slice(0, 10) };
}
async function api(req, res, url) {
  const { pathname } = url;
  if (req.method === "POST" && pathname === "/api/login") { const b = await body(req), u = store.data.users.find(x => x.email.toLowerCase() === String(b.email).toLowerCase() && x.active); if (!u || !passwordMatches(b.password || "", u.password)) return json(res, 401, { error: "Invalid email or password" }); res.writeHead(200, { "Content-Type": "application/json", "Set-Cookie": `session=${token(u)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800` }); return res.end(JSON.stringify({ user: publicUser(u) })); }
  if (req.method === "POST" && pathname === "/api/logout") { res.writeHead(204, { "Set-Cookie": "session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0" }); return res.end(); }
  if (req.method === "GET" && pathname === "/api/me") { const u = userFromToken(parseCookies(req).session, store.data); return u ? json(res, 200, { user: publicUser(u) }) : json(res, 401, { error: "Not signed in" }); }
  const signedIn = userFromToken(parseCookies(req).session, store.data);
  if (req.method === "GET" && pathname === "/api/teacher/assignments") { if (!signedIn || signedIn.role !== roles.TEACHER) return json(res, signedIn ? 403 : 401, { error: "Teacher access required" }); const teacher = store.data.teachers.find(t => t.userId === signedIn.id); return json(res, 200, { assignments: teacher ? teacher.assignments : [] }); }
  if (req.method === "GET" && pathname === "/api/parent/student") { if (!signedIn || signedIn.role !== roles.PARENT) return json(res, signedIn ? 403 : 401, { error: "Parent access required" }); const student = store.data.students.find(s => s.id === signedIn.studentId); return student ? json(res, 200, { student }) : json(res, 404, { error: "Linked student not found" }); }
  const admin = requireRole(req, res, [roles.ADMIN]); if (!admin) return;
  if (req.method === "GET" && pathname === "/api/dashboard") return json(res, 200, dashboard());
  if (req.method === "GET" && pathname === "/api/teachers") return json(res, 200, store.data.teachers.map(t => ({ ...t, user: publicUser(store.data.users.find(u => u.id === t.userId)) })));
  if (req.method === "POST" && pathname === "/api/teachers") { const b = await body(req); if (!b.name || !b.email) return json(res, 400, { error: "Name and email are required" }); if (store.data.users.some(u => u.email === b.email)) return json(res, 409, { error: "Email already exists" }); const u = { id: id("usr"), name: b.name, email: b.email, role: roles.TEACHER, password: passwordHash(b.password || "Welcome123!"), active: true }; const t = { id: id("teacher"), userId: u.id, employeeId: b.employeeId || `T-${Date.now()}`, phone: b.phone || "", assignments: b.assignments || [], active: true }; store.data.users.push(u); store.data.teachers.push(t); store.audit(admin, "CREATE", "teacher", t.id, `Created ${u.email}`); return json(res, 201, { teacher: t, credentials: { email: u.email, temporaryPassword: b.password || "Welcome123!" } }); }
  const teacherToggle = pathname.match(/^\/api\/teachers\/([^/]+)\/active$/); if (req.method === "PATCH" && teacherToggle) { const t = store.data.teachers.find(x => x.id === teacherToggle[1]); if (!t) return json(res, 404, { error: "Teacher not found" }); const b = await body(req); t.active = Boolean(b.active); store.data.users.find(u => u.id === t.userId).active = t.active; store.audit(admin, t.active ? "ACTIVATE" : "DEACTIVATE", "teacher", t.id); return json(res, 200, { teacher: t }); }
  const teacherUpdate = pathname.match(/^\/api\/teachers\/([^/]+)$/); if (req.method === "PATCH" && teacherUpdate) { const t = store.data.teachers.find(x => x.id === teacherUpdate[1]); if (!t) return json(res, 404, { error: "Teacher not found" }); const b = await body(req), u = store.data.users.find(x => x.id === t.userId); if (b.name) u.name = b.name; if (b.phone !== undefined) t.phone = b.phone; if (b.assignments) t.assignments = b.assignments; store.audit(admin, "UPDATE", "teacher", t.id, "Profile or workload updated"); store.save(); return json(res, 200, { teacher: t }); }
  if (req.method === "GET" && pathname === "/api/students") return json(res, 200, store.data.students);
  if (req.method === "POST" && pathname === "/api/students") { const b = await body(req); if (!b.name || !b.classId || !b.sectionId || !b.parentEmail) return json(res, 400, { error: "Name, class, section, and parent email are required" }); if (store.data.users.some(u => u.email === b.parentEmail)) return json(res, 409, { error: "Parent email already exists" }); const s = { id: id("student"), studentId: nextStudentId(), name: b.name, classId: b.classId, sectionId: b.sectionId, status: "active", parentName: b.parentName || "", parentPhone: b.parentPhone || "", parentEmail: b.parentEmail, yearId: store.data.activeYearId, history: [] }; const p = { id: id("usr"), name: b.parentName || `${b.name}'s Parent`, email: b.parentEmail, role: roles.PARENT, password: passwordHash(b.password || "Welcome123!"), active: true, studentId: s.id }; store.data.students.push(s); store.data.users.push(p); store.audit(admin, "REGISTER", "student", s.id, `${s.studentId}: ${s.name}`); return json(res, 201, { student: s, credentials: { email: p.email, temporaryPassword: b.password || "Welcome123!" } }); }
  const promote = pathname.match(/^\/api\/students\/([^/]+)\/promote$/); if (req.method === "POST" && promote) { const s = store.data.students.find(x => x.id === promote[1]); if (!s) return json(res, 404, { error: "Student not found" }); const b = await body(req); s.history.push({ yearId: s.yearId, classId: s.classId, sectionId: s.sectionId, completedAt: new Date().toISOString() }); s.classId = b.classId; s.sectionId = b.sectionId; s.yearId = b.yearId || store.data.activeYearId; store.audit(admin, "PROMOTE", "student", s.id); store.save(); return json(res, 200, { student: s }); }
  const studentUpdate = pathname.match(/^\/api\/students\/([^/]+)$/); if (req.method === "PATCH" && studentUpdate) { const s = store.data.students.find(x => x.id === studentUpdate[1]); if (!s) return json(res, 404, { error: "Student not found" }); const b = await body(req); ["name", "parentName", "parentPhone", "parentEmail", "status", "classId", "sectionId"].forEach(k => { if (b[k] !== undefined) s[k] = b[k]; }); const parent = store.data.users.find(u => u.studentId === s.id); if (parent && b.parentEmail) parent.email = b.parentEmail; store.audit(admin, "UPDATE", "student", s.id, "Enrollment or contact updated"); store.save(); return json(res, 200, { student: s }); }
  if (req.method === "GET" && pathname === "/api/classes") return json(res, 200, store.data.classes);
  if (req.method === "POST" && pathname === "/api/classes") { const b = await body(req); const c = { id: id("class"), name: b.name, active: true, sections: (b.sections || []).map(name => ({ id: id("section"), name, classTeacherId: null })) }; if (!c.name) return json(res, 400, { error: "Class name is required" }); store.data.classes.push(c); store.audit(admin, "CREATE", "class", c.id); store.save(); return json(res, 201, c); }
  const classUpdate = pathname.match(/^\/api\/classes\/([^/]+)$/); if (req.method === "PATCH" && classUpdate) { const c = store.data.classes.find(x => x.id === classUpdate[1]); if (!c) return json(res, 404, { error: "Class not found" }); const b = await body(req); if (b.name) c.name = b.name; if (b.active !== undefined) c.active = Boolean(b.active); store.audit(admin, "UPDATE", "class", c.id); store.save(); return json(res, 200, c); }
  const sectionAdd = pathname.match(/^\/api\/classes\/([^/]+)\/sections$/); if (req.method === "POST" && sectionAdd) { const c = store.data.classes.find(x => x.id === sectionAdd[1]), b = await body(req); if (!c) return json(res, 404, { error: "Class not found" }); if (!b.name) return json(res, 400, { error: "Section name is required" }); const section = { id: id("section"), name: b.name, classTeacherId: b.classTeacherId || null }; c.sections.push(section); store.audit(admin, "CREATE", "section", section.id, `Added to ${c.name}`); store.save(); return json(res, 201, section); }
  if (req.method === "GET" && pathname === "/api/subjects") return json(res, 200, store.data.subjects);
  if (req.method === "POST" && pathname === "/api/subjects") { const b = await body(req); if (!b.name) return json(res, 400, { error: "Subject name is required" }); const subject = { id: id("subject"), name: b.name, classIds: b.classIds || [], teacherId: b.teacherId || null, maxMarks: Number(b.maxMarks || 100), gradingRules: b.gradingRules || "" }; store.data.subjects.push(subject); store.audit(admin, "CREATE", "subject", subject.id); store.save(); return json(res, 201, subject); }
  const subjectUpdate = pathname.match(/^\/api\/subjects\/([^/]+)$/); if (req.method === "PATCH" && subjectUpdate) { const subject = store.data.subjects.find(x => x.id === subjectUpdate[1]); if (!subject) return json(res, 404, { error: "Subject not found" }); const b = await body(req); ["name", "classIds", "teacherId", "maxMarks", "gradingRules"].forEach(k => { if (b[k] !== undefined) subject[k] = b[k]; }); store.audit(admin, "UPDATE", "subject", subject.id); store.save(); return json(res, 200, subject); }
  if (req.method === "GET" && pathname === "/api/years") return json(res, 200, store.data.years);
  if (req.method === "POST" && pathname === "/api/years") { const b = await body(req); const year = { id: id("year"), name: b.name, active: false }; if (!year.name) return json(res, 400, { error: "Academic-year name is required" }); store.data.years.push(year); store.audit(admin, "CREATE", "academic-year", year.id); store.save(); return json(res, 201, year); }
  const activeYear = pathname.match(/^\/api\/years\/([^/]+)\/active$/); if (req.method === "PATCH" && activeYear) { const year = store.data.years.find(y => y.id === activeYear[1]); if (!year) return json(res, 404, { error: "Academic year not found" }); store.data.years.forEach(y => y.active = y.id === year.id); store.data.activeYearId = year.id; store.audit(admin, "SET_ACTIVE", "academic-year", year.id); store.save(); return json(res, 200, year); }
  if (req.method === "GET" && pathname === "/api/audit") return json(res, 200, store.data.audit);
  return json(res, 404, { error: "Not found" });
}
const server = http.createServer(async (req, res) => { try { const url = new URL(req.url, `http://${req.headers.host}`); if (url.pathname.startsWith("/api/")) return api(req, res, url); const requested = url.pathname === "/" ? "/public/index.html" : `/public${url.pathname}`; const file = path.normalize(path.join(ROOT, requested)); if (!file.startsWith(path.join(ROOT, "public"))) return json(res, 403, { error: "Forbidden" }); const types = { ".html": "text/html; charset=utf-8", ".js": "application/javascript; charset=utf-8", ".css": "text/css; charset=utf-8" }; fs.readFile(file, (err, content) => err ? json(res, 404, { error: "Not found" }) : (res.writeHead(200, { "Content-Type": types[path.extname(file)] || "application/octet-stream" }), res.end(content))); } catch (e) { json(res, 400, { error: e.message }); } });
server.listen(PORT, () => console.log(`School Portal running at http://localhost:${PORT}`));
