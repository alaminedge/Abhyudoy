// functions/api/[[route]].js
// Abhyudoy EdTech Platform API

async function sha256(text) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join('');
}

const SECRET = 'abhyudoy_edtech_secret_2024';

async function signToken(payload) {
  const header = btoa(JSON.stringify({ alg:'HS256', typ:'JWT' }));
  const body = btoa(JSON.stringify(payload));
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(SECRET),
    { name:'HMAC', hash:'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`${header}.${body}`));
  return `${header}.${body}.${btoa(String.fromCharCode(...new Uint8Array(sig)))}`;
}

async function verifyToken(token) {
  try {
    const [header, body, sig] = token.split('.');
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(SECRET),
      { name:'HMAC', hash:'SHA-256' }, false, ['verify']);
    const sigBuf = Uint8Array.from(atob(sig), c => c.charCodeAt(0));
    const valid = await crypto.subtle.verify('HMAC', key, sigBuf,
      new TextEncoder().encode(`${header}.${body}`));
    if (!valid) return null;
    const payload = JSON.parse(atob(body));
    if (payload.exp && Date.now() > payload.exp) return null;
    return payload;
  } catch { return null; }
}

async function getUser(request) {
  const auth = request.headers.get('Authorization') || '';
  const token = auth.replace('Bearer ', '').trim();
  if (!token) return null;
  return verifyToken(token);
}

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization',
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type':'application/json', ...CORS }
  });
}

function err(msg, status = 400) {
  return json({ error: msg }, status);
}

async function ensureTables(db) {
  // Users
  await db.prepare(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'user',
    is_blocked INTEGER DEFAULT 0,
    is_approved INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`).run();

  // Device fingerprints
  await db.prepare(`CREATE TABLE IF NOT EXISTS device_registrations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_fingerprint TEXT NOT NULL,
    user_id INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`).run();

  // Courses
  await db.prepare(`CREATE TABLE IF NOT EXISTS courses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    subject_name TEXT NOT NULL,
    paper_type TEXT,
    description TEXT,
    thumbnail TEXT,
    is_active INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`).run();

  // Chapters
  await db.prepare(`CREATE TABLE IF NOT EXISTS chapters (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    course_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    sort_order INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (course_id) REFERENCES courses(id) ON DELETE CASCADE
  )`).run();

  // Lectures
  await db.prepare(`CREATE TABLE IF NOT EXISTS lectures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chapter_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    yt_video_id TEXT NOT NULL,
    sort_order INTEGER DEFAULT 0,
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (chapter_id) REFERENCES chapters(id) ON DELETE CASCADE
  )`).run();

  // Lecture PDFs
  await db.prepare(`CREATE TABLE IF NOT EXISTS lecture_pdfs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    lecture_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    pdf_url TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (lecture_id) REFERENCES lectures(id) ON DELETE CASCADE
  )`).run();

  // Resources
  await db.prepare(`CREATE TABLE IF NOT EXISTS resources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    course_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    pdf_url TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (course_id) REFERENCES courses(id) ON DELETE CASCADE
  )`).run();

  // Memberships
  await db.prepare(`CREATE TABLE IF NOT EXISTS memberships (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    course_id INTEGER NOT NULL,
    expires_at DATETIME NOT NULL,
    is_active INTEGER DEFAULT 1,
    granted_by INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, course_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (course_id) REFERENCES courses(id) ON DELETE CASCADE
  )`).run();

  // Default admin
  const adminHash = await sha256('123admin');
  await db.prepare(`INSERT OR IGNORE INTO users (name, email, password, role, is_approved)
    VALUES ('Admin', 'cnct.nx@gmail.com', ?, 'admin', 1)`).bind(adminHash).run();
}

// ═══ AUTH ROUTES ═══
async function handleAuth(method, path, body, db) {
  // Signup
  if (method === 'POST' && path === '/signup') {
    const { name, email, password, device_fingerprint } = body;
    if (!name || !email || !password) return err('All fields required');
    if (password.length < 6) return err('Password must be 6+ characters');

    // Check device fingerprint
    if (device_fingerprint) {
      const existing = await db.prepare(
        'SELECT COUNT(*) as cnt FROM device_registrations WHERE device_fingerprint = ?'
      ).bind(device_fingerprint).first();
      if (existing.cnt > 0) return err('An account already exists on this device', 403);
    }

    const hashed = await sha256(password);
    try {
      const result = await db.prepare(
        'INSERT INTO users (name, email, password) VALUES (?, ?, ?)'
      ).bind(name.trim(), email.toLowerCase().trim(), hashed).run();

      if (device_fingerprint) {
        await db.prepare(
          'INSERT INTO device_registrations (device_fingerprint, user_id) VALUES (?, ?)'
        ).bind(device_fingerprint, result.meta.last_row_id).run();
      }

      return json({ message: 'Account created! Awaiting admin approval.' }, 201);
    } catch (e) {
      if (e.message?.includes('UNIQUE')) return err('Email already registered');
      return err('Signup failed');
    }
  }

  // Login
  if (method === 'POST' && path === '/login') {
    const { email, password } = body;
    if (!email || !password) return err('Email and password required');
    const hashed = await sha256(password);
    const user = await db.prepare(
      'SELECT * FROM users WHERE email = ? AND password = ?'
    ).bind(email.toLowerCase().trim(), hashed).first();
    if (!user) return err('Invalid email or password', 401);
    if (user.is_blocked) return err('Account blocked. Contact support.', 403);
    if (!user.is_approved) return err('Account pending admin approval.', 403);

    const token = await signToken({
      id: user.id, email: user.email, role: user.role,
      exp: Date.now() + 30 * 24 * 60 * 60 * 1000
    });
    return json({
      token,
      user: {
        id: user.id, name: user.name, email: user.email,
        role: user.role, is_approved: user.is_approved
      }
    });
  }

  return err('Auth route not found', 404);
}

// ═══ USER ROUTES ═══
async function handleUser(method, path, body, db, user) {
  if (!user) return err('Unauthorized', 401);

  // My Courses
  if (method === 'GET' && path === '/my-courses') {
    const courses = await db.prepare(`
      SELECT c.*, m.expires_at, m.is_active as membership_active
      FROM memberships m
      JOIN courses c ON m.course_id = c.id
      WHERE m.user_id = ? AND m.is_active = 1 AND m.expires_at > datetime('now')
        AND c.is_active = 1
      ORDER BY m.created_at DESC
    `).bind(user.id).all();
    return json(courses.results);
  }

  // Course Detail (with chapters, lectures, resources)
  if (method === 'GET' && path.match(/^\/course\/\d+$/)) {
    const courseId = parseInt(path.split('/')[2]);

    // Check membership
    const membership = await db.prepare(`
      SELECT * FROM memberships WHERE user_id = ? AND course_id = ? AND is_active = 1 AND expires_at > datetime('now')
    `).bind(user.id, courseId).first();
    if (!membership && user.role !== 'admin') return err('No active membership for this course', 403);

    const course = await db.prepare('SELECT * FROM courses WHERE id = ?').bind(courseId).first();
    if (!course) return err('Course not found', 404);

    const chapters = await db.prepare(
      'SELECT * FROM chapters WHERE course_id = ? ORDER BY sort_order ASC'
    ).bind(courseId).all();

    // Get lectures for each chapter
    for (const ch of chapters.results) {
      ch.lectures = (await db.prepare(
        'SELECT * FROM lectures WHERE chapter_id = ? ORDER BY sort_order ASC'
      ).bind(ch.id).all()).results;
      // Get PDFs for each lecture
      for (const lec of ch.lectures) {
        lec.pdfs = (await db.prepare(
          'SELECT * FROM lecture_pdfs WHERE lecture_id = ?'
        ).bind(lec.id).all()).results;
      }
    }

    const resources = await db.prepare(
      'SELECT * FROM resources WHERE course_id = ? ORDER BY created_at DESC'
    ).bind(courseId).all();

    return json({
      course,
      chapters: chapters.results,
      resources: resources.results,
      membership: { expires_at: membership?.expires_at }
    });
  }

  // Get single lecture
  if (method === 'GET' && path.match(/^\/lecture\/\d+$/)) {
    const lectureId = parseInt(path.split('/')[2]);
    const lecture = await db.prepare(`
      SELECT l.*, ch.course_id
      FROM lectures l
      JOIN chapters ch ON l.chapter_id = ch.id
      WHERE l.id = ?
    `).bind(lectureId).first();
    if (!lecture) return err('Lecture not found', 404);

    // Check membership
    const membership = await db.prepare(`
      SELECT * FROM memberships WHERE user_id = ? AND course_id = ? AND is_active = 1 AND expires_at > datetime('now')
    `).bind(user.id, lecture.course_id).first();
    if (!membership && user.role !== 'admin') return err('No active membership', 403);

    // Get all lectures in this course (for sidebar)
    const allLectures = await db.prepare(`
      SELECT l.*, ch.title as chapter_title, ch.course_id
      FROM lectures l
      JOIN chapters ch ON l.chapter_id = ch.id
      WHERE ch.course_id = ?
      ORDER BY ch.sort_order ASC, l.sort_order ASC
    `).bind(lecture.course_id).all();

    const pdfs = await db.prepare(
      'SELECT * FROM lecture_pdfs WHERE lecture_id = ?'
    ).bind(lectureId).all();

    return json({
      lecture,
      allLectures: allLectures.results,
      pdfs: pdfs.results
    });
  }

  return err('User route not found', 404);
}

// ═══ ADMIN ROUTES ═══
async function handleAdmin(method, path, body, db, user) {
  if (!user) return err('Unauthorized', 401);
  if (user.role !== 'admin') return err('Admin access required', 403);

  // Users list
  if (method === 'GET' && path === '/users') {
    const u = await db.prepare(
      'SELECT id, name, email, role, is_blocked, is_approved, created_at FROM users ORDER BY created_at DESC'
    ).all();
    return json(u.results);
  }

  // Approve user
  if (method === 'PUT' && path.match(/^\/users\/\d+\/approve$/)) {
    const userId = parseInt(path.split('/')[2]);
    await db.prepare('UPDATE users SET is_approved = 1 WHERE id = ?').bind(userId).run();
    return json({ message: 'User approved' });
  }

  // Block/Unblock user
  if (method === 'PUT' && path.match(/^\/users\/\d+\/block$/)) {
    const userId = parseInt(path.split('/')[2]);
    const { is_blocked } = body;
    await db.prepare('UPDATE users SET is_blocked = ? WHERE id = ?').bind(is_blocked ? 1 : 0, userId).run();
    return json({ message: is_blocked ? 'User blocked' : 'User unblocked' });
  }

  // Delete user
  if (method === 'DELETE' && path.match(/^\/users\/\d+$/)) {
    const userId = parseInt(path.split('/')[2]);
    await db.prepare('DELETE FROM memberships WHERE user_id = ?').bind(userId).run();
    await db.prepare('DELETE FROM device_registrations WHERE user_id = ?').bind(userId).run();
    await db.prepare('DELETE FROM users WHERE id = ? AND role != \'admin\'').bind(userId).run();
    return json({ message: 'User deleted' });
  }

  // Courses CRUD
  if (method === 'GET' && path === '/courses') {
    const courses = await db.prepare('SELECT * FROM courses ORDER BY created_at DESC').all();
    return json(courses.results);
  }

  if (method === 'POST' && path === '/courses') {
    const { title, subject_name, paper_type, description, thumbnail } = body;
    if (!title || !subject_name) return err('Title and subject are required');
    const result = await db.prepare(
      'INSERT INTO courses (title, subject_name, paper_type, description, thumbnail) VALUES (?, ?, ?, ?, ?)'
    ).bind(title, subject_name, paper_type || null, description || '', thumbnail || '').run();
    return json({ id: result.meta.last_row_id, message: 'Course created' }, 201);
  }

  if (method === 'PUT' && path.match(/^\/courses\/\d+$/)) {
    const courseId = parseInt(path.split('/')[2]);
    const { title, subject_name, paper_type, description, thumbnail, is_active } = body;
    const updates = []; const values = [];
    if (title !== undefined) { updates.push('title = ?'); values.push(title); }
    if (subject_name !== undefined) { updates.push('subject_name = ?'); values.push(subject_name); }
    if (paper_type !== undefined) { updates.push('paper_type = ?'); values.push(paper_type); }
    if (description !== undefined) { updates.push('description = ?'); values.push(description); }
    if (thumbnail !== undefined) { updates.push('thumbnail = ?'); values.push(thumbnail); }
    if (is_active !== undefined) { updates.push('is_active = ?'); values.push(is_active); }
    updates.push('updated_at = ?'); values.push(new Date().toISOString());
    if (!updates.length) return err('Nothing to update');
    values.push(courseId);
    await db.prepare(`UPDATE courses SET ${updates.join(', ')} WHERE id = ?`).bind(...values).run();
    return json({ message: 'Course updated' });
  }

  if (method === 'DELETE' && path.match(/^\/courses\/\d+$/)) {
    const courseId = parseInt(path.split('/')[2]);
    await db.prepare('DELETE FROM resources WHERE course_id = ?').bind(courseId).run();
    await db.prepare('DELETE FROM memberships WHERE course_id = ?').bind(courseId).run();
    // Delete lectures via chapters
    const chapters = await db.prepare('SELECT id FROM chapters WHERE course_id = ?').bind(courseId).all();
    for (const ch of chapters.results) {
      await db.prepare('DELETE FROM lecture_pdfs WHERE lecture_id IN (SELECT id FROM lectures WHERE chapter_id = ?)').bind(ch.id).run();
    }
    await db.prepare('DELETE FROM lectures WHERE chapter_id IN (SELECT id FROM chapters WHERE course_id = ?)').bind(courseId).run();
    await db.prepare('DELETE FROM chapters WHERE course_id = ?').bind(courseId).run();
    await db.prepare('DELETE FROM courses WHERE id = ?').bind(courseId).run();
    return json({ message: 'Course deleted' });
  }

  // Chapters CRUD
  if (method === 'GET' && path.match(/^\/chapters\/course\/\d+$/)) {
    const courseId = parseInt(path.split('/')[3]);
    const chapters = await db.prepare(
      'SELECT * FROM chapters WHERE course_id = ? ORDER BY sort_order ASC'
    ).bind(courseId).all();
    return json(chapters.results);
  }

  if (method === 'POST' && path === '/chapters') {
    const { course_id, title, sort_order } = body;
    if (!course_id || !title) return err('Course and title required');
    const result = await db.prepare(
      'INSERT INTO chapters (course_id, title, sort_order) VALUES (?, ?, ?)'
    ).bind(course_id, title, sort_order || 0).run();
    return json({ id: result.meta.last_row_id, message: 'Chapter created' }, 201);
  }

  if (method === 'PUT' && path.match(/^\/chapters\/\d+$/)) {
    const chId = parseInt(path.split('/')[2]);
    const { title, sort_order } = body;
    const updates = []; const values = [];
    if (title !== undefined) { updates.push('title = ?'); values.push(title); }
    if (sort_order !== undefined) { updates.push('sort_order = ?'); values.push(sort_order); }
    if (!updates.length) return err('Nothing to update');
    values.push(chId);
    await db.prepare(`UPDATE chapters SET ${updates.join(', ')} WHERE id = ?`).bind(...values).run();
    return json({ message: 'Chapter updated' });
  }

  if (method === 'DELETE' && path.match(/^\/chapters\/\d+$/)) {
    const chId = parseInt(path.split('/')[2]);
    await db.prepare('DELETE FROM lecture_pdfs WHERE lecture_id IN (SELECT id FROM lectures WHERE chapter_id = ?)').bind(chId).run();
    await db.prepare('DELETE FROM lectures WHERE chapter_id = ?').bind(chId).run();
    await db.prepare('DELETE FROM chapters WHERE id = ?').bind(chId).run();
    return json({ message: 'Chapter deleted' });
  }

  // Lectures CRUD
  if (method === 'GET' && path.match(/^\/lectures\/chapter\/\d+$/)) {
    const chId = parseInt(path.split('/')[3]);
    const lectures = await db.prepare(
      'SELECT * FROM lectures WHERE chapter_id = ? ORDER BY sort_order ASC'
    ).bind(chId).all();
    return json(lectures.results);
  }

  if (method === 'POST' && path === '/lectures') {
    const { chapter_id, title, yt_video_id, sort_order, description } = body;
    if (!chapter_id || !title || !yt_video_id) return err('Chapter, title, and YouTube ID required');
    const result = await db.prepare(
      'INSERT INTO lectures (chapter_id, title, yt_video_id, sort_order, description) VALUES (?, ?, ?, ?, ?)'
    ).bind(chapter_id, title, yt_video_id, sort_order || 0, description || '').run();
    return json({ id: result.meta.last_row_id, message: 'Lecture created' }, 201);
  }

  if (method === 'PUT' && path.match(/^\/lectures\/\d+$/)) {
    const lecId = parseInt(path.split('/')[2]);
    const { title, yt_video_id, sort_order, description } = body;
    const updates = []; const values = [];
    if (title !== undefined) { updates.push('title = ?'); values.push(title); }
    if (yt_video_id !== undefined) { updates.push('yt_video_id = ?'); values.push(yt_video_id); }
    if (sort_order !== undefined) { updates.push('sort_order = ?'); values.push(sort_order); }
    if (description !== undefined) { updates.push('description = ?'); values.push(description); }
    updates.push('updated_at = ?'); values.push(new Date().toISOString());
    if (!updates.length) return err('Nothing to update');
    values.push(lecId);
    await db.prepare(`UPDATE lectures SET ${updates.join(', ')} WHERE id = ?`).bind(...values).run();
    return json({ message: 'Lecture updated' });
  }

  if (method === 'DELETE' && path.match(/^\/lectures\/\d+$/)) {
    const lecId = parseInt(path.split('/')[2]);
    await db.prepare('DELETE FROM lecture_pdfs WHERE lecture_id = ?').bind(lecId).run();
    await db.prepare('DELETE FROM lectures WHERE id = ?').bind(lecId).run();
    return json({ message: 'Lecture deleted' });
  }

  // Lecture PDFs
  if (method === 'POST' && path === '/lecture-pdfs') {
    const { lecture_id, title, pdf_url } = body;
    if (!lecture_id || !title || !pdf_url) return err('All fields required');
    const result = await db.prepare(
      'INSERT INTO lecture_pdfs (lecture_id, title, pdf_url) VALUES (?, ?, ?)'
    ).bind(lecture_id, title, pdf_url).run();
    return json({ id: result.meta.last_row_id, message: 'PDF added' }, 201);
  }

  if (method === 'DELETE' && path.match(/^\/lecture-pdfs\/\d+$/)) {
    await db.prepare('DELETE FROM lecture_pdfs WHERE id = ?').bind(parseInt(path.split('/')[2])).run();
    return json({ message: 'PDF deleted' });
  }

  // Resources CRUD
  if (method === 'GET' && path.match(/^\/resources\/course\/\d+$/)) {
    const courseId = parseInt(path.split('/')[3]);
    const resources = await db.prepare(
      'SELECT * FROM resources WHERE course_id = ? ORDER BY created_at DESC'
    ).bind(courseId).all();
    return json(resources.results);
  }

  if (method === 'POST' && path === '/resources') {
    const { course_id, title, pdf_url } = body;
    if (!course_id || !title || !pdf_url) return err('All fields required');
    const result = await db.prepare(
      'INSERT INTO resources (course_id, title, pdf_url) VALUES (?, ?, ?)'
    ).bind(course_id, title, pdf_url).run();
    return json({ id: result.meta.last_row_id, message: 'Resource added' }, 201);
  }

  if (method === 'DELETE' && path.match(/^\/resources\/\d+$/)) {
    await db.prepare('DELETE FROM resources WHERE id = ?').bind(parseInt(path.split('/')[2])).run();
    return json({ message: 'Resource deleted' });
  }

  // Memberships
  if (method === 'GET' && path === '/memberships') {
    const memberships = await db.prepare(`
      SELECT m.*, u.name as user_name, u.email as user_email, c.title as course_title, c.subject_name
      FROM memberships m
      JOIN users u ON m.user_id = u.id
      JOIN courses c ON m.course_id = c.id
      ORDER BY m.created_at DESC
    `).all();
    return json(memberships.results);
  }

  if (method === 'POST' && path === '/memberships') {
    const { user_id, course_id, days } = body;
    if (!user_id || !course_id || !days) return err('All fields required');
    const expires_at = new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString();
    try {
      await db.prepare(
        'INSERT OR REPLACE INTO memberships (user_id, course_id, expires_at, granted_by) VALUES (?, ?, ?, ?)'
      ).bind(user_id, course_id, expires_at, user.id).run();
      return json({ message: 'Membership granted', expires_at }, 201);
    } catch (e) {
      return err('Failed to grant membership: ' + e.message);
    }
  }

  if (method === 'PUT' && path.match(/^\/memberships\/\d+\/extend$/)) {
    const memId = parseInt(path.split('/')[2]);
    const { days } = body;
    if (!days) return err('Days required');
    await db.prepare(
      `UPDATE memberships SET expires_at = datetime(expires_at, '+' || ? || ' days'), is_active = 1 WHERE id = ?`
    ).bind(days, memId).run();
    return json({ message: 'Membership extended' });
  }

  if (method === 'PUT' && path.match(/^\/memberships\/\d+\/cancel$/)) {
    const memId = parseInt(path.split('/')[2]);
    await db.prepare('UPDATE memberships SET is_active = 0 WHERE id = ?').bind(memId).run();
    return json({ message: 'Membership cancelled' });
  }

  return err('Admin route not found', 404);
}

// ═══ MAIN ═══
export async function onRequest(context) {
  const { request, env } = context;
  const db = env.ABHYUDOY_DB;

  if (request.method === 'OPTIONS') return new Response(null, { headers: CORS });

  await ensureTables(db);

  const url = new URL(request.url);
  const fullPath = url.pathname.replace(/^\/api/, '');

  let body = {};
  if (['POST','PUT','DELETE'].includes(request.method)) {
    try { body = await request.json(); } catch {}
  }

  const authUser = await getUser(request);

  if (fullPath.startsWith('/auth/')) return handleAuth(request.method, fullPath.replace('/auth',''), body, db);
  if (fullPath.startsWith('/user/')) return handleUser(request.method, fullPath.replace('/user',''), body, db, authUser);
  if (fullPath.startsWith('/admin/')) return handleAdmin(request.method, fullPath.replace('/admin',''), body, db, authUser);

  return err('API route not found', 404);
}
