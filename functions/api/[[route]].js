// functions/api/[[route]].js
// Abhyudoy EdTech Platform — Complete API (Fixed)

async function sha256(text) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join('');
}

const SECRET = 'abhyudoy_2024_secret';

async function signToken(payload) {
  const header = btoa(JSON.stringify({ alg:'HS256', typ:'JWT' }));
  const body = btoa(JSON.stringify(payload));
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(SECRET),
    { name:'HMAC', hash:'SHA-256' }, false, ['sign']);
  const sig = btoa(String.fromCharCode(...new Uint8Array(
    await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`${header}.${body}`))
  )));
  return `${header}.${body}.${sig}`;
}

async function verifyToken(token) {
  try {
    const [header, body, sig] = token.split('.');
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(SECRET),
      { name:'HMAC', hash:'SHA-256' }, false, ['verify']);
    const valid = await crypto.subtle.verify('HMAC', key,
      Uint8Array.from(atob(sig), c => c.charCodeAt(0)),
      new TextEncoder().encode(`${header}.${body}`)
    );
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
    headers: { 'Content-Type': 'application/json', ...CORS }
  });
}
function err(msg, status = 400) { return json({ error: msg }, status); }

// ─────────────────────────────────────────────
// TABLE SETUP
// ─────────────────────────────────────────────
async function ensureTables(db) {
  await db.prepare(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL, role TEXT DEFAULT 'user',
    is_blocked INTEGER DEFAULT 0, is_approved INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`).run();

  await db.prepare(`CREATE TABLE IF NOT EXISTS device_registrations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_fingerprint TEXT NOT NULL, user_id INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`).run();

  await db.prepare(`CREATE TABLE IF NOT EXISTS courses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL, description TEXT, thumbnail TEXT,
    is_active INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`).run();

  await db.prepare(`CREATE TABLE IF NOT EXISTS subjects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    course_id INTEGER NOT NULL, name TEXT NOT NULL,
    has_papers INTEGER DEFAULT 1, sort_order INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`).run();

  await db.prepare(`CREATE TABLE IF NOT EXISTS papers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subject_id INTEGER NOT NULL, name TEXT NOT NULL,
    sort_order INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`).run();

  await db.prepare(`CREATE TABLE IF NOT EXISTS chapters (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    paper_id INTEGER NOT NULL, title TEXT NOT NULL,
    sort_order INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`).run();

  await db.prepare(`CREATE TABLE IF NOT EXISTS lectures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chapter_id INTEGER NOT NULL, title TEXT NOT NULL,
    yt_video_id TEXT NOT NULL, sort_order INTEGER DEFAULT 0,
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`).run();

  await db.prepare(`CREATE TABLE IF NOT EXISTS lecture_pdfs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    lecture_id INTEGER NOT NULL, title TEXT NOT NULL, pdf_url TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`).run();

  await db.prepare(`CREATE TABLE IF NOT EXISTS resources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    course_id INTEGER NOT NULL, title TEXT NOT NULL, pdf_url TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`).run();

  await db.prepare(`CREATE TABLE IF NOT EXISTS memberships (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL, course_id INTEGER NOT NULL,
    expires_at DATETIME NOT NULL, is_active INTEGER DEFAULT 1,
    granted_by INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, course_id)
  )`).run();

  // Default admin: password = admin123
  const adminHash = await sha256('admin123');
  await db.prepare(`INSERT OR IGNORE INTO users (name, email, password, role, is_approved)
    VALUES ('Admin', 'cnct.nx@gmail.com', ?, 'admin', 1)`).bind(adminHash).run();
}

// ─────────────────────────────────────────────
// AUTH
// ─────────────────────────────────────────────
async function handleAuth(method, path, body, db) {
  if (method === 'POST' && path === '/signup') {
    const { name, email, password, device_fingerprint } = body;
    if (!name || !email || !password) return err('All fields required');
    if (password.length < 6) return err('Password must be 6+ characters');

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

  if (method === 'POST' && path === '/login') {
    const { email, password } = body;
    if (!email || !password) return err('Email and password required');
    const hashed = await sha256(password);
    const user = await db.prepare(
      'SELECT * FROM users WHERE email = ? AND password = ?'
    ).bind(email.toLowerCase().trim(), hashed).first();
    if (!user) return err('Invalid email or password', 401);
    if (user.is_blocked) return err('Your account has been suspended. Contact support.', 403);
    if (!user.is_approved) return err('Your account is pending admin approval.', 403);
    const token = await signToken({
      id: user.id, email: user.email, role: user.role,
      exp: Date.now() + 30 * 24 * 60 * 60 * 1000
    });
    return json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
  }

  return err('Auth route not found', 404);
}

// ─────────────────────────────────────────────
// USER
// ─────────────────────────────────────────────
async function handleUser(method, path, body, db, user) {
  if (!user) return err('Unauthorized — please sign in', 401);

  // GET /api/user/my-courses
  if (method === 'GET' && path === '/my-courses') {
    const courses = await db.prepare(`
      SELECT c.*, m.expires_at, m.id as membership_id
      FROM memberships m
      JOIN courses c ON m.course_id = c.id
      WHERE m.user_id = ? AND m.is_active = 1
        AND m.expires_at > datetime('now') AND c.is_active = 1
      ORDER BY m.created_at DESC
    `).bind(user.id).all();
    return json(courses.results);
  }

  // GET /api/user/course/:id
  if (method === 'GET' && path.match(/^\/course\/\d+$/)) {
    const courseId = parseInt(path.split('/')[2]);

    // Check membership (admin bypasses)
    if (user.role !== 'admin') {
      const membership = await db.prepare(
        `SELECT * FROM memberships WHERE user_id = ? AND course_id = ?
         AND is_active = 1 AND expires_at > datetime('now')`
      ).bind(user.id, courseId).first();
      if (!membership) return err('No active membership for this course', 403);
    }

    const course = await db.prepare('SELECT * FROM courses WHERE id = ? AND is_active = 1').bind(courseId).first();
    if (!course) return err('Course not found', 404);

    const subjects = await db.prepare(
      'SELECT * FROM subjects WHERE course_id = ? ORDER BY sort_order ASC, id ASC'
    ).bind(courseId).all();

    for (const subj of subjects.results) {
      subj.papers = (await db.prepare(
        'SELECT * FROM papers WHERE subject_id = ? ORDER BY sort_order ASC, id ASC'
      ).bind(subj.id).all()).results;

      for (const paper of subj.papers) {
        paper.chapters = (await db.prepare(
          'SELECT * FROM chapters WHERE paper_id = ? ORDER BY sort_order ASC, id ASC'
        ).bind(paper.id).all()).results;

        for (const ch of paper.chapters) {
          ch.lectures = (await db.prepare(
            'SELECT * FROM lectures WHERE chapter_id = ? ORDER BY sort_order ASC, id ASC'
          ).bind(ch.id).all()).results;

          for (const lec of ch.lectures) {
            lec.pdfs = (await db.prepare(
              'SELECT * FROM lecture_pdfs WHERE lecture_id = ?'
            ).bind(lec.id).all()).results;
          }
        }
      }
    }

    const resources = await db.prepare(
      'SELECT * FROM resources WHERE course_id = ? ORDER BY created_at DESC'
    ).bind(courseId).all();

    const membership = user.role === 'admin' ? null : await db.prepare(
      `SELECT * FROM memberships WHERE user_id = ? AND course_id = ?
       AND is_active = 1 ORDER BY expires_at DESC LIMIT 1`
    ).bind(user.id, courseId).first();

    return json({
      course,
      subjects: subjects.results,
      resources: resources.results,
      membership: membership ? { expires_at: membership.expires_at } : { expires_at: null }
    });
  }

  // GET /api/user/lecture/:id
  if (method === 'GET' && path.match(/^\/lecture\/\d+$/)) {
    const lectureId = parseInt(path.split('/')[2]);

    const lecture = await db.prepare(`
      SELECT l.*, ch.title as chapter_title, ch.id as chapter_id,
             p.name as paper_name, p.id as paper_id,
             s.name as subject_name, s.id as subject_id, s.course_id
      FROM lectures l
      JOIN chapters ch ON l.chapter_id = ch.id
      JOIN papers p ON ch.paper_id = p.id
      JOIN subjects s ON p.subject_id = s.id
      WHERE l.id = ?
    `).bind(lectureId).first();

    if (!lecture) return err('Lecture not found', 404);

    if (user.role !== 'admin') {
      const membership = await db.prepare(
        `SELECT * FROM memberships WHERE user_id = ? AND course_id = ?
         AND is_active = 1 AND expires_at > datetime('now')`
      ).bind(user.id, lecture.course_id).first();
      if (!membership) return err('No active membership', 403);
    }

    const allLectures = await db.prepare(`
      SELECT l.*, ch.title as chapter_title, ch.id as chapter_id,
             p.name as paper_name, s.name as subject_name
      FROM lectures l
      JOIN chapters ch ON l.chapter_id = ch.id
      JOIN papers p ON ch.paper_id = p.id
      JOIN subjects s ON p.subject_id = s.id
      WHERE s.course_id = ?
      ORDER BY s.sort_order ASC, s.id ASC,
               p.sort_order ASC, p.id ASC,
               ch.sort_order ASC, ch.id ASC,
               l.sort_order ASC, l.id ASC
    `).bind(lecture.course_id).all();

    const pdfs = await db.prepare(
      'SELECT * FROM lecture_pdfs WHERE lecture_id = ? ORDER BY created_at ASC'
    ).bind(lectureId).all();

    return json({
      lecture,
      allLectures: allLectures.results,
      pdfs: pdfs.results
    });
  }

  return err('User route not found', 404);
}

// ─────────────────────────────────────────────
// ADMIN
// ─────────────────────────────────────────────
async function handleAdmin(method, path, body, db, user) {
  if (!user) return err('Unauthorized', 401);
  if (user.role !== 'admin') return err('Admin access required', 403);

  // ── COURSES ──
  if (method === 'GET' && path === '/courses') {
    const r = await db.prepare('SELECT * FROM courses ORDER BY created_at DESC').all();
    return json(r.results);
  }
  if (method === 'POST' && path === '/courses') {
    const { title, description, thumbnail, is_active } = body;
    if (!title) return err('Title required');
    const r = await db.prepare(
      'INSERT INTO courses (title, description, thumbnail, is_active) VALUES (?, ?, ?, ?)'
    ).bind(title, description || '', thumbnail || null, is_active !== undefined ? is_active : 1).run();
    return json({ id: r.meta.last_row_id, message: 'Course created' }, 201);
  }
  if (method === 'PUT' && path.match(/^\/courses\/\d+$/)) {
    const courseId = parseInt(path.split('/')[2]);
    const { title, description, thumbnail, is_active } = body;
    const u = [], v = [];
    if (title !== undefined) { u.push('title = ?'); v.push(title); }
    if (description !== undefined) { u.push('description = ?'); v.push(description); }
    if (thumbnail !== undefined) { u.push('thumbnail = ?'); v.push(thumbnail); }
    if (is_active !== undefined) { u.push('is_active = ?'); v.push(is_active); }
    u.push('updated_at = ?'); v.push(new Date().toISOString());
    v.push(courseId);
    await db.prepare(`UPDATE courses SET ${u.join(', ')} WHERE id = ?`).bind(...v).run();
    return json({ message: 'Course updated' });
  }
  if (method === 'DELETE' && path.match(/^\/courses\/\d+$/)) {
    const courseId = parseInt(path.split('/')[2]);
    // Full cascade delete
    const subjs = await db.prepare('SELECT id FROM subjects WHERE course_id = ?').bind(courseId).all();
    for (const s of subjs.results) {
      const papers = await db.prepare('SELECT id FROM papers WHERE subject_id = ?').bind(s.id).all();
      for (const p of papers.results) {
        const chs = await db.prepare('SELECT id FROM chapters WHERE paper_id = ?').bind(p.id).all();
        for (const c of chs.results) {
          await db.prepare('DELETE FROM lecture_pdfs WHERE lecture_id IN (SELECT id FROM lectures WHERE chapter_id = ?)').bind(c.id).run();
          await db.prepare('DELETE FROM lectures WHERE chapter_id = ?').bind(c.id).run();
        }
        await db.prepare('DELETE FROM chapters WHERE paper_id = ?').bind(p.id).run();
      }
      await db.prepare('DELETE FROM papers WHERE subject_id = ?').bind(s.id).run();
    }
    await db.prepare('DELETE FROM subjects WHERE course_id = ?').bind(courseId).run();
    await db.prepare('DELETE FROM resources WHERE course_id = ?').bind(courseId).run();
    await db.prepare('DELETE FROM memberships WHERE course_id = ?').bind(courseId).run();
    await db.prepare('DELETE FROM courses WHERE id = ?').bind(courseId).run();
    return json({ message: 'Course deleted' });
  }

  // ── SUBJECTS ──
  if (method === 'GET' && path === '/all-subjects') {
    const r = await db.prepare('SELECT * FROM subjects ORDER BY course_id ASC, sort_order ASC').all();
    return json(r.results);
  }
  if (method === 'GET' && path.match(/^\/subjects\/course\/\d+$/)) {
    const courseId = parseInt(path.split('/')[3]);
    const r = await db.prepare('SELECT * FROM subjects WHERE course_id = ? ORDER BY sort_order ASC').bind(courseId).all();
    return json(r.results);
  }
  if (method === 'POST' && path === '/subjects') {
    const { course_id, name, has_papers, sort_order } = body;
    if (!course_id || !name) return err('Course and name required');
    const r = await db.prepare(
      'INSERT INTO subjects (course_id, name, has_papers, sort_order) VALUES (?, ?, ?, ?)'
    ).bind(course_id, name, has_papers !== undefined ? has_papers : 1, sort_order || 0).run();
    const subjId = r.meta.last_row_id;
    // If no papers mode, auto-create default paper
    if (!has_papers || has_papers === 0) {
      await db.prepare('INSERT INTO papers (subject_id, name, sort_order) VALUES (?, ?, ?)')
        .bind(subjId, 'Full Course', 0).run();
    }
    return json({ id: subjId, message: 'Subject created' }, 201);
  }
  if (method === 'DELETE' && path.match(/^\/subjects\/\d+$/)) {
    const subjId = parseInt(path.split('/')[2]);
    const papers = await db.prepare('SELECT id FROM papers WHERE subject_id = ?').bind(subjId).all();
    for (const p of papers.results) {
      const chs = await db.prepare('SELECT id FROM chapters WHERE paper_id = ?').bind(p.id).all();
      for (const c of chs.results) {
        await db.prepare('DELETE FROM lecture_pdfs WHERE lecture_id IN (SELECT id FROM lectures WHERE chapter_id = ?)').bind(c.id).run();
        await db.prepare('DELETE FROM lectures WHERE chapter_id = ?').bind(c.id).run();
      }
      await db.prepare('DELETE FROM chapters WHERE paper_id = ?').bind(p.id).run();
    }
    await db.prepare('DELETE FROM papers WHERE subject_id = ?').bind(subjId).run();
    await db.prepare('DELETE FROM subjects WHERE id = ?').bind(subjId).run();
    return json({ message: 'Subject deleted' });
  }

  // ── PAPERS ──
  if (method === 'GET' && path === '/all-papers') {
    const r = await db.prepare('SELECT * FROM papers ORDER BY subject_id ASC, sort_order ASC').all();
    return json(r.results);
  }
  if (method === 'GET' && path.match(/^\/papers\/subject\/\d+$/)) {
    const subjId = parseInt(path.split('/')[3]);
    const r = await db.prepare('SELECT * FROM papers WHERE subject_id = ? ORDER BY sort_order ASC').bind(subjId).all();
    return json(r.results);
  }
  if (method === 'POST' && path === '/papers') {
    const { subject_id, name, sort_order } = body;
    if (!subject_id || !name) return err('Subject and name required');
    const r = await db.prepare('INSERT INTO papers (subject_id, name, sort_order) VALUES (?, ?, ?)')
      .bind(subject_id, name, sort_order || 0).run();
    return json({ id: r.meta.last_row_id, message: 'Paper created' }, 201);
  }
  if (method === 'DELETE' && path.match(/^\/papers\/\d+$/)) {
    const paperId = parseInt(path.split('/')[2]);
    const chs = await db.prepare('SELECT id FROM chapters WHERE paper_id = ?').bind(paperId).all();
    for (const c of chs.results) {
      await db.prepare('DELETE FROM lecture_pdfs WHERE lecture_id IN (SELECT id FROM lectures WHERE chapter_id = ?)').bind(c.id).run();
      await db.prepare('DELETE FROM lectures WHERE chapter_id = ?').bind(c.id).run();
    }
    await db.prepare('DELETE FROM chapters WHERE paper_id = ?').bind(paperId).run();
    await db.prepare('DELETE FROM papers WHERE id = ?').bind(paperId).run();
    return json({ message: 'Paper deleted' });
  }

  // ── CHAPTERS ──
  if (method === 'GET' && path === '/all-chapters') {
    const r = await db.prepare('SELECT * FROM chapters ORDER BY paper_id ASC, sort_order ASC').all();
    return json(r.results);
  }
  if (method === 'GET' && path.match(/^\/chapters\/paper\/\d+$/)) {
    const paperId = parseInt(path.split('/')[3]);
    const r = await db.prepare('SELECT * FROM chapters WHERE paper_id = ? ORDER BY sort_order ASC').bind(paperId).all();
    return json(r.results);
  }
  if (method === 'POST' && path === '/chapters') {
    const { paper_id, title, sort_order } = body;
    if (!paper_id || !title) return err('Paper and title required');
    const r = await db.prepare('INSERT INTO chapters (paper_id, title, sort_order) VALUES (?, ?, ?)')
      .bind(paper_id, title, sort_order || 0).run();
    return json({ id: r.meta.last_row_id, message: 'Chapter created' }, 201);
  }
  if (method === 'DELETE' && path.match(/^\/chapters\/\d+$/)) {
    const chId = parseInt(path.split('/')[2]);
    await db.prepare('DELETE FROM lecture_pdfs WHERE lecture_id IN (SELECT id FROM lectures WHERE chapter_id = ?)').bind(chId).run();
    await db.prepare('DELETE FROM lectures WHERE chapter_id = ?').bind(chId).run();
    await db.prepare('DELETE FROM chapters WHERE id = ?').bind(chId).run();
    return json({ message: 'Chapter deleted' });
  }

  // ── LECTURES ──
  if (method === 'GET' && path === '/all-lectures') {
    const r = await db.prepare(`
      SELECT l.*, ch.title as chapter_title, p.name as paper_name, s.name as subject_name, s.course_id
      FROM lectures l
      JOIN chapters ch ON l.chapter_id = ch.id
      JOIN papers p ON ch.paper_id = p.id
      JOIN subjects s ON p.subject_id = s.id
      ORDER BY l.created_at DESC
    `).all();
    return json(r.results);
  }
  if (method === 'GET' && path.match(/^\/lectures\/chapter\/\d+$/)) {
    const chId = parseInt(path.split('/')[3]);
    const r = await db.prepare('SELECT * FROM lectures WHERE chapter_id = ? ORDER BY sort_order ASC').bind(chId).all();
    return json(r.results);
  }
  if (method === 'POST' && path === '/lectures') {
    const { chapter_id, title, yt_video_id, sort_order, description } = body;
    if (!chapter_id || !title || !yt_video_id) return err('Chapter, title, and YouTube ID required');
    const r = await db.prepare(
      'INSERT INTO lectures (chapter_id, title, yt_video_id, sort_order, description) VALUES (?, ?, ?, ?, ?)'
    ).bind(chapter_id, title, yt_video_id, sort_order || 0, description || '').run();
    return json({ id: r.meta.last_row_id, message: 'Lecture created' }, 201);
  }
  if (method === 'PUT' && path.match(/^\/lectures\/\d+$/)) {
    const lecId = parseInt(path.split('/')[2]);
    const { title, yt_video_id, sort_order, description } = body;
    const u = [], v = [];
    if (title !== undefined) { u.push('title = ?'); v.push(title); }
    if (yt_video_id !== undefined) { u.push('yt_video_id = ?'); v.push(yt_video_id); }
    if (sort_order !== undefined) { u.push('sort_order = ?'); v.push(sort_order); }
    if (description !== undefined) { u.push('description = ?'); v.push(description); }
    u.push('updated_at = ?'); v.push(new Date().toISOString());
    v.push(lecId);
    await db.prepare(`UPDATE lectures SET ${u.join(', ')} WHERE id = ?`).bind(...v).run();
    return json({ message: 'Lecture updated' });
  }
  if (method === 'DELETE' && path.match(/^\/lectures\/\d+$/)) {
    const lecId = parseInt(path.split('/')[2]);
    await db.prepare('DELETE FROM lecture_pdfs WHERE lecture_id = ?').bind(lecId).run();
    await db.prepare('DELETE FROM lectures WHERE id = ?').bind(lecId).run();
    return json({ message: 'Lecture deleted' });
  }

  // ── LECTURE PDFs ──
  if (method === 'POST' && path === '/lecture-pdfs') {
    const { lecture_id, title, pdf_url } = body;
    if (!lecture_id || !title || !pdf_url) return err('All fields required');
    const r = await db.prepare('INSERT INTO lecture_pdfs (lecture_id, title, pdf_url) VALUES (?, ?, ?)')
      .bind(lecture_id, title, pdf_url).run();
    return json({ id: r.meta.last_row_id, message: 'PDF added' }, 201);
  }
  if (method === 'DELETE' && path.match(/^\/lecture-pdfs\/\d+$/)) {
    await db.prepare('DELETE FROM lecture_pdfs WHERE id = ?').bind(parseInt(path.split('/')[2])).run();
    return json({ message: 'PDF deleted' });
  }

  // ── RESOURCES ──
  if (method === 'GET' && path.match(/^\/resources\/course\/\d+$/)) {
    const courseId = parseInt(path.split('/')[3]);
    const r = await db.prepare('SELECT * FROM resources WHERE course_id = ? ORDER BY created_at DESC').bind(courseId).all();
    return json(r.results);
  }
  if (method === 'POST' && path === '/resources') {
    const { course_id, title, pdf_url } = body;
    if (!course_id || !title || !pdf_url) return err('All fields required');
    const r = await db.prepare('INSERT INTO resources (course_id, title, pdf_url) VALUES (?, ?, ?)')
      .bind(course_id, title, pdf_url).run();
    return json({ id: r.meta.last_row_id, message: 'Resource added' }, 201);
  }
  if (method === 'DELETE' && path.match(/^\/resources\/\d+$/)) {
    await db.prepare('DELETE FROM resources WHERE id = ?').bind(parseInt(path.split('/')[2])).run();
    return json({ message: 'Resource deleted' });
  }

  // ── USERS ──
  if (method === 'GET' && path === '/users') {
    const r = await db.prepare(
      'SELECT id, name, email, role, is_blocked, is_approved, created_at FROM users ORDER BY created_at DESC'
    ).all();
    return json(r.results);
  }
  if (method === 'PUT' && path.match(/^\/users\/\d+\/approve$/)) {
    await db.prepare('UPDATE users SET is_approved = 1 WHERE id = ?').bind(parseInt(path.split('/')[2])).run();
    return json({ message: 'User approved' });
  }
  if (method === 'PUT' && path.match(/^\/users\/\d+\/block$/)) {
    const { is_blocked } = body;
    await db.prepare('UPDATE users SET is_blocked = ? WHERE id = ?').bind(is_blocked ? 1 : 0, parseInt(path.split('/')[2])).run();
    return json({ message: is_blocked ? 'User blocked' : 'User unblocked' });
  }
  if (method === 'DELETE' && path.match(/^\/users\/\d+$/)) {
    const userId = parseInt(path.split('/')[2]);
    await db.prepare('DELETE FROM memberships WHERE user_id = ?').bind(userId).run();
    await db.prepare('DELETE FROM device_registrations WHERE user_id = ?').bind(userId).run();
    await db.prepare("DELETE FROM users WHERE id = ? AND role != 'admin'").bind(userId).run();
    return json({ message: 'User deleted' });
  }

  // ── MEMBERSHIPS ──
  if (method === 'GET' && path === '/memberships') {
    const r = await db.prepare(`
      SELECT m.*, u.name as user_name, u.email as user_email, c.title as course_title
      FROM memberships m
      JOIN users u ON m.user_id = u.id
      JOIN courses c ON m.course_id = c.id
      ORDER BY m.created_at DESC
    `).all();
    return json(r.results);
  }
  if (method === 'POST' && path === '/memberships') {
    const { user_id, course_id, days } = body;
    if (!user_id || !course_id || !days) return err('user_id, course_id, and days required');
    const expires_at = new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString();
    await db.prepare(
      'INSERT OR REPLACE INTO memberships (user_id, course_id, expires_at, is_active, granted_by) VALUES (?, ?, ?, 1, ?)'
    ).bind(user_id, course_id, expires_at, user.id).run();
    return json({ message: 'Membership granted', expires_at }, 201);
  }
  if (method === 'PUT' && path.match(/^\/memberships\/\d+\/extend$/)) {
    const { days } = body;
    if (!days) return err('Days required');
    await db.prepare(
      `UPDATE memberships SET expires_at = datetime(
        CASE WHEN expires_at < datetime('now') THEN datetime('now') ELSE expires_at END,
        '+' || ? || ' days'
      ), is_active = 1 WHERE id = ?`
    ).bind(days, parseInt(path.split('/')[2])).run();
    return json({ message: 'Membership extended' });
  }
  if (method === 'PUT' && path.match(/^\/memberships\/\d+\/cancel$/)) {
    await db.prepare('UPDATE memberships SET is_active = 0 WHERE id = ?').bind(parseInt(path.split('/')[2])).run();
    return json({ message: 'Membership cancelled' });
  }

  return err('Admin route not found', 404);
}

// ─────────────────────────────────────────────
// MAIN HANDLER
// ─────────────────────────────────────────────
export async function onRequest(context) {
  const { request, env } = context;
  const db = env.ABHYUDOY_DB;

  if (request.method === 'OPTIONS') return new Response(null, { headers: CORS });

  await ensureTables(db);

  const url = new URL(request.url);
  const fullPath = url.pathname.replace(/^\/api/, '');

  let body = {};
  if (['POST', 'PUT', 'DELETE'].includes(request.method)) {
    try { body = await request.json(); } catch {}
  }

  const authUser = await getUser(request);

  if (fullPath.startsWith('/auth/')) return handleAuth(request.method, fullPath.replace('/auth', ''), body, db);
  if (fullPath.startsWith('/user/')) return handleUser(request.method, fullPath.replace('/user', ''), body, db, authUser);
  if (fullPath.startsWith('/admin/')) return handleAdmin(request.method, fullPath.replace('/admin', ''), body, db, authUser);

  return err('API route not found', 404);
}
