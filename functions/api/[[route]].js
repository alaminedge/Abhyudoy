// Abhyudoy EdTech - Complete API v2

async function sha256(text) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join('');
}

const SECRET = 'abhyudoy_v2_secret_2024';

async function signToken(payload) {
  const header = btoa(JSON.stringify({ alg:'HS256', typ:'JWT' }));
  const body = btoa(JSON.stringify(payload));
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(SECRET), { name:'HMAC', hash:'SHA-256' }, false, ['sign']);
  const sig = btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`${header}.${body}`)))));
  return `${header}.${body}.${sig}`;
}

async function verifyToken(token) {
  try {
    const [header, body, sig] = token.split('.');
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(SECRET), { name:'HMAC', hash:'SHA-256' }, false, ['verify']);
    const valid = await crypto.subtle.verify('HMAC', key, Uint8Array.from(atob(sig), c => c.charCodeAt(0)), new TextEncoder().encode(`${header}.${body}`));
    if(!valid) return null;
    const payload = JSON.parse(atob(body));
    if(payload.exp && Date.now() > payload.exp) return null;
    return payload;
  } catch { return null; }
}

async function getUser(request) {
  const auth = request.headers.get('Authorization') || '';
  const token = auth.replace('Bearer ', '').trim();
  return token ? verifyToken(token) : null;
}

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization'
};

function json(data, status=200) {
  return new Response(JSON.stringify(data), { status, headers: { 'Content-Type':'application/json', ...CORS } });
}

function err(msg, status=400) { return json({error:msg}, status); }

async function ensureTables(db) {
  // Users
  await db.exec(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, password TEXT NOT NULL, role TEXT DEFAULT 'user', is_blocked INTEGER DEFAULT 0, is_approved INTEGER DEFAULT 0, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`);
  // Device
  await db.exec(`CREATE TABLE IF NOT EXISTS device_registrations (id INTEGER PRIMARY KEY AUTOINCREMENT, device_fingerprint TEXT NOT NULL, user_id INTEGER, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`);
  // Courses
  await db.exec(`CREATE TABLE IF NOT EXISTS courses (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, description TEXT, thumbnail TEXT, is_active INTEGER DEFAULT 1, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP)`);
  // Subjects
  await db.exec(`CREATE TABLE IF NOT EXISTS subjects (id INTEGER PRIMARY KEY AUTOINCREMENT, course_id INTEGER NOT NULL, name TEXT NOT NULL, has_papers INTEGER DEFAULT 1, sort_order INTEGER DEFAULT 0, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (course_id) REFERENCES courses(id) ON DELETE CASCADE)`);
  // Papers
  await db.exec(`CREATE TABLE IF NOT EXISTS papers (id INTEGER PRIMARY KEY AUTOINCREMENT, subject_id INTEGER NOT NULL, name TEXT NOT NULL, sort_order INTEGER DEFAULT 0, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (subject_id) REFERENCES subjects(id) ON DELETE CASCADE)`);
  // Chapters
  await db.exec(`CREATE TABLE IF NOT EXISTS chapters (id INTEGER PRIMARY KEY AUTOINCREMENT, paper_id INTEGER NOT NULL, title TEXT NOT NULL, sort_order INTEGER DEFAULT 0, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (paper_id) REFERENCES papers(id) ON DELETE CASCADE)`);
  // Lectures
  await db.exec(`CREATE TABLE IF NOT EXISTS lectures (id INTEGER PRIMARY KEY AUTOINCREMENT, chapter_id INTEGER NOT NULL, title TEXT NOT NULL, yt_video_id TEXT NOT NULL, pdf_url TEXT, sort_order INTEGER DEFAULT 0, description TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (chapter_id) REFERENCES chapters(id) ON DELETE CASCADE)`);
  // Resources
  await db.exec(`CREATE TABLE IF NOT EXISTS resources (id INTEGER PRIMARY KEY AUTOINCREMENT, course_id INTEGER NOT NULL, title TEXT NOT NULL, pdf_url TEXT NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (course_id) REFERENCES courses(id) ON DELETE CASCADE)`);
  // Memberships
  await db.exec(`CREATE TABLE IF NOT EXISTS memberships (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, course_id INTEGER NOT NULL, expires_at DATETIME NOT NULL, is_active INTEGER DEFAULT 1, granted_by INTEGER, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, UNIQUE(user_id, course_id), FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE, FOREIGN KEY (course_id) REFERENCES courses(id) ON DELETE CASCADE)`);
  
  const hash = await sha256('123admin');
  await db.exec(`INSERT OR IGNORE INTO users (name, email, password, role, is_approved) VALUES ('Admin', 'cnct.nx@gmail.com', '${hash}', 'admin', 1)`);
}

// ═══ AUTH ═══
async function handleAuth(method, path, body, db) {
  if(method==='POST' && path==='/signup') {
    const {name, email, password, device_fingerprint} = body;
    if(!name||!email||!password) return err('All fields required');
    if(password.length<6) return err('Password 6+ characters');
    if(device_fingerprint) {
      const r = await db.prepare('SELECT COUNT(*) as cnt FROM device_registrations WHERE device_fingerprint=?').bind(device_fingerprint).first();
      if(r.cnt>0) return err('Account already exists on this device', 403);
    }
    const hash = await sha256(password);
    try {
      const r = await db.prepare('INSERT INTO users (name,email,password) VALUES (?,?,?)').bind(name.trim(), email.toLowerCase().trim(), hash).run();
      if(device_fingerprint) await db.prepare('INSERT INTO device_registrations (device_fingerprint,user_id) VALUES (?,?)').bind(device_fingerprint, r.meta.last_row_id).run();
      return json({message:'Account created! Awaiting admin approval.'}, 201);
    } catch(e) {
      if(e.message?.includes('UNIQUE')) return err('Email already registered');
      return err('Signup failed');
    }
  }
  if(method==='POST' && path==='/login') {
    const {email, password} = body;
    if(!email||!password) return err('Email and password required');
    const hash = await sha256(password);
    const user = await db.prepare('SELECT * FROM users WHERE email=? AND password=?').bind(email.toLowerCase().trim(), hash).first();
    if(!user) return err('Invalid credentials', 401);
    if(user.is_blocked) return err('Account blocked', 403);
    if(!user.is_approved) return err('Account pending approval', 403);
    const token = await signToken({id:user.id, email:user.email, role:user.role, exp:Date.now()+30*24*60*60*1000});
    return json({token, user:{id:user.id, name:user.name, email:user.email, role:user.role}});
  }
  return err('Not found', 404);
}

// ═══ USER ═══
async function handleUser(method, path, body, db, user) {
  if(!user) return err('Unauthorized', 401);
  
  if(method==='GET' && path==='/my-courses') {
    const r = await db.prepare(`SELECT c.*, m.expires_at FROM memberships m JOIN courses c ON m.course_id=c.id WHERE m.user_id=? AND m.is_active=1 AND m.expires_at>datetime('now') AND c.is_active=1 ORDER BY m.created_at DESC`).bind(user.id).all();
    return json(r.results);
  }
  
  if(method==='GET' && path.match(/^\/course\/\d+$/)) {
    const courseId = parseInt(path.split('/')[2]);
    const mem = await db.prepare(`SELECT * FROM memberships WHERE user_id=? AND course_id=? AND is_active=1 AND expires_at>datetime('now')`).bind(user.id, courseId).first();
    if(!mem && user.role!=='admin') return err('No active membership', 403);
    const course = await db.prepare('SELECT * FROM courses WHERE id=?').bind(courseId).first();
    if(!course) return err('Course not found', 404);
    const subjects = await db.prepare('SELECT * FROM subjects WHERE course_id=? ORDER BY sort_order').bind(courseId).all();
    for(const s of subjects.results) {
      s.papers = (await db.prepare('SELECT * FROM papers WHERE subject_id=? ORDER BY sort_order').bind(s.id).all()).results;
      for(const p of s.papers) {
        p.chapters = (await db.prepare('SELECT * FROM chapters WHERE paper_id=? ORDER BY sort_order').bind(p.id).all()).results;
        for(const c of p.chapters) {
          c.lectures = (await db.prepare('SELECT * FROM lectures WHERE chapter_id=? ORDER BY sort_order').bind(c.id).all()).results;
        }
      }
    }
    const resources = await db.prepare('SELECT * FROM resources WHERE course_id=? ORDER BY created_at DESC').bind(courseId).all();
    return json({course, subjects:subjects.results, resources:resources.results, membership:{expires_at:mem?.expires_at}});
  }
  
  if(method==='GET' && path.match(/^\/lecture\/\d+$/)) {
    const lectureId = parseInt(path.split('/')[2]);
    const lecture = await db.prepare(`SELECT l.*, ch.title as chapter_title, p.name as paper_name, s.name as subject_name, s.course_id FROM lectures l JOIN chapters ch ON l.chapter_id=ch.id JOIN papers p ON ch.paper_id=p.id JOIN subjects s ON p.subject_id=s.id WHERE l.id=?`).bind(lectureId).first();
    if(!lecture) return err('Lecture not found', 404);
    const mem = await db.prepare(`SELECT * FROM memberships WHERE user_id=? AND course_id=? AND is_active=1 AND expires_at>datetime('now')`).bind(user.id, lecture.course_id).first();
    if(!mem && user.role!=='admin') return err('No active membership', 403);
    const allLectures = await db.prepare(`SELECT l.*, ch.title as chapter_title, p.name as paper_name, s.name as subject_name FROM lectures l JOIN chapters ch ON l.chapter_id=ch.id JOIN papers p ON ch.paper_id=p.id JOIN subjects s ON p.subject_id=s.id WHERE s.course_id=? ORDER BY s.sort_order, p.sort_order, ch.sort_order, l.sort_order`).bind(lecture.course_id).all();
    return json({lecture, allLectures:allLectures.results});
  }
  return err('Not found', 404);
}

// ═══ ADMIN ═══
async function handleAdmin(method, path, body, db, user) {
  if(!user) return err('Unauthorized', 401);
  if(user.role!=='admin') return err('Admin only', 403);

  // Courses
  if(method==='GET' && path==='/courses') { const r = await db.prepare('SELECT * FROM courses ORDER BY created_at DESC').all(); return json(r.results); }
  if(method==='POST' && path==='/courses') { const {title,description} = body; if(!title) return err('Title required'); const r = await db.prepare('INSERT INTO courses (title,description) VALUES (?,?)').bind(title,description||'').run(); return json({id:r.meta.last_row_id,message:'Course created'},201); }
  if(method==='PUT' && path.match(/^\/courses\/\d+$/)) { const id=parseInt(path.split('/')[2]); const {title,description,is_active}=body; const u=[]; const v=[]; if(title!==undefined){u.push('title=?');v.push(title);} if(description!==undefined){u.push('description=?');v.push(description);} if(is_active!==undefined){u.push('is_active=?');v.push(is_active);} u.push('updated_at=?');v.push(new Date().toISOString()); v.push(id); await db.prepare(`UPDATE courses SET ${u.join(',')} WHERE id=?`).bind(...v).run(); return json({message:'Updated'}); }
  if(method==='DELETE' && path.match(/^\/courses\/\d+$/)) { const id=parseInt(path.split('/')[2]); await db.exec(`DELETE FROM memberships WHERE course_id=${id}; DELETE FROM resources WHERE course_id=${id}; DELETE FROM lectures WHERE chapter_id IN (SELECT id FROM chapters WHERE paper_id IN (SELECT id FROM papers WHERE subject_id IN (SELECT id FROM subjects WHERE course_id=${id}))); DELETE FROM chapters WHERE paper_id IN (SELECT id FROM papers WHERE subject_id IN (SELECT id FROM subjects WHERE course_id=${id})); DELETE FROM papers WHERE subject_id IN (SELECT id FROM subjects WHERE course_id=${id}); DELETE FROM subjects WHERE course_id=${id}; DELETE FROM courses WHERE id=${id}`); return json({message:'Deleted'}); }

  // Subjects
  if(method==='GET' && path==='/subjects') { const r = await db.prepare('SELECT s.*, c.title as course_title FROM subjects s JOIN courses c ON s.course_id=c.id ORDER BY c.title, s.sort_order').all(); return json(r.results); }
  if(method==='POST' && path==='/subjects') { const {course_id,name,has_papers}=body; if(!course_id||!name) return err('Course and name required'); const r = await db.prepare('INSERT INTO subjects (course_id,name,has_papers) VALUES (?,?,?)').bind(course_id,name,has_papers!==undefined?has_papers:1).run(); if(!has_papers) await db.prepare('INSERT INTO papers (subject_id,name,sort_order) VALUES (?,\'Full Course\',0)').bind(r.meta.last_row_id).run(); return json({id:r.meta.last_row_id,message:'Subject created'},201); }
  if(method==='DELETE' && path.match(/^\/subjects\/\d+$/)) { const id=parseInt(path.split('/')[2]); await db.exec(`DELETE FROM lectures WHERE chapter_id IN (SELECT id FROM chapters WHERE paper_id IN (SELECT id FROM papers WHERE subject_id=${id})); DELETE FROM chapters WHERE paper_id IN (SELECT id FROM papers WHERE subject_id=${id}); DELETE FROM papers WHERE subject_id=${id}; DELETE FROM subjects WHERE id=${id}`); return json({message:'Deleted'}); }

  // Papers
  if(method==='GET' && path==='/papers') { const r = await db.prepare('SELECT p.*, s.name as subject_name, c.title as course_title FROM papers p JOIN subjects s ON p.subject_id=s.id JOIN courses c ON s.course_id=c.id ORDER BY c.title, s.name, p.sort_order').all(); return json(r.results); }
  if(method==='POST' && path==='/papers') { const {subject_id,name}=body; if(!subject_id||!name) return err('Subject and name required'); const r = await db.prepare('INSERT INTO papers (subject_id,name) VALUES (?,?)').bind(subject_id,name).run(); return json({id:r.meta.last_row_id,message:'Paper created'},201); }
  if(method==='DELETE' && path.match(/^\/papers\/\d+$/)) { const id=parseInt(path.split('/')[2]); await db.exec(`DELETE FROM lectures WHERE chapter_id IN (SELECT id FROM chapters WHERE paper_id=${id}); DELETE FROM chapters WHERE paper_id=${id}; DELETE FROM papers WHERE id=${id}`); return json({message:'Deleted'}); }

  // Chapters
  if(method==='GET' && path==='/chapters') { const r = await db.prepare('SELECT ch.*, p.name as paper_name, s.name as subject_name FROM chapters ch JOIN papers p ON ch.paper_id=p.id JOIN subjects s ON p.subject_id=s.id ORDER BY s.name, p.name, ch.sort_order').all(); return json(r.results); }
  if(method==='POST' && path==='/chapters') { const {paper_id,title}=body; if(!paper_id||!title) return err('Paper and title required'); const r = await db.prepare('INSERT INTO chapters (paper_id,title) VALUES (?,?)').bind(paper_id,title).run(); return json({id:r.meta.last_row_id,message:'Chapter created'},201); }
  if(method==='DELETE' && path.match(/^\/chapters\/\d+$/)) { const id=parseInt(path.split('/')[2]); await db.exec(`DELETE FROM lectures WHERE chapter_id=${id}; DELETE FROM chapters WHERE id=${id}`); return json({message:'Deleted'}); }

  // Lectures (with pdf_url field)
  if(method==='GET' && path==='/lectures') { const r = await db.prepare('SELECT l.*, ch.title as chapter_title, p.name as paper_name, s.name as subject_name, c.title as course_title FROM lectures l JOIN chapters ch ON l.chapter_id=ch.id JOIN papers p ON ch.paper_id=p.id JOIN subjects s ON p.subject_id=s.id JOIN courses c ON s.course_id=c.id ORDER BY l.created_at DESC').all(); return json(r.results); }
  if(method==='POST' && path==='/lectures') { const {chapter_id,title,yt_video_id,pdf_url,description}=body; if(!chapter_id||!title||!yt_video_id) return err('Chapter, title, YT ID required'); const r = await db.prepare('INSERT INTO lectures (chapter_id,title,yt_video_id,pdf_url,description) VALUES (?,?,?,?,?)').bind(chapter_id,title,yt_video_id,pdf_url||null,description||'').run(); return json({id:r.meta.last_row_id,message:'Lecture created'},201); }
  if(method==='PUT' && path.match(/^\/lectures\/\d+$/)) { const id=parseInt(path.split('/')[2]); const {title,yt_video_id,pdf_url,description}=body; const u=[]; const v=[]; if(title!==undefined){u.push('title=?');v.push(title);} if(yt_video_id!==undefined){u.push('yt_video_id=?');v.push(yt_video_id);} if(pdf_url!==undefined){u.push('pdf_url=?');v.push(pdf_url);} if(description!==undefined){u.push('description=?');v.push(description);} u.push('updated_at=?');v.push(new Date().toISOString()); v.push(id); await db.prepare(`UPDATE lectures SET ${u.join(',')} WHERE id=?`).bind(...v).run(); return json({message:'Updated'}); }
  if(method==='DELETE' && path.match(/^\/lectures\/\d+$/)) { const id=parseInt(path.split('/')[2]); await db.exec(`DELETE FROM lectures WHERE id=${id}`); return json({message:'Deleted'}); }

  // Resources
  if(method==='GET' && path.match(/^\/resources\/\d+$/)) { const r = await db.prepare('SELECT * FROM resources WHERE course_id=? ORDER BY created_at DESC').bind(parseInt(path.split('/')[2])).all(); return json(r.results); }
  if(method==='POST' && path==='/resources') { const {course_id,title,pdf_url}=body; if(!course_id||!title||!pdf_url) return err('All fields required'); const r = await db.prepare('INSERT INTO resources (course_id,title,pdf_url) VALUES (?,?,?)').bind(course_id,title,pdf_url).run(); return json({id:r.meta.last_row_id,message:'Resource added'},201); }
  if(method==='DELETE' && path.match(/^\/resources\/\d+$/)) { await db.prepare('DELETE FROM resources WHERE id=?').bind(parseInt(path.split('/')[2])).run(); return json({message:'Deleted'}); }

  // Users
  if(method==='GET' && path==='/users') { const r = await db.prepare('SELECT id,name,email,role,is_blocked,is_approved,created_at FROM users ORDER BY created_at DESC').all(); return json(r.results); }
  if(method==='PUT' && path.match(/^\/users\/\d+\/approve$/)) { await db.prepare('UPDATE users SET is_approved=1 WHERE id=?').bind(parseInt(path.split('/')[2])).run(); return json({message:'Approved'}); }
  if(method==='PUT' && path.match(/^\/users\/\d+\/block$/)) { const {is_blocked}=body; await db.prepare('UPDATE users SET is_blocked=? WHERE id=?').bind(is_blocked?1:0, parseInt(path.split('/')[2])).run(); return json({message:is_blocked?'Blocked':'Unblocked'}); }
  if(method==='DELETE' && path.match(/^\/users\/\d+$/)) { const id=parseInt(path.split('/')[2]); await db.exec(`DELETE FROM memberships WHERE user_id=${id}; DELETE FROM device_registrations WHERE user_id=${id}; DELETE FROM users WHERE id=${id} AND role!='admin'`); return json({message:'Deleted'}); }

  // Memberships
  if(method==='GET' && path==='/memberships') { const r = await db.prepare('SELECT m.*, u.name as user_name, c.title as course_title FROM memberships m JOIN users u ON m.user_id=u.id JOIN courses c ON m.course_id=c.id ORDER BY m.created_at DESC').all(); return json(r.results); }
  if(method==='POST' && path==='/memberships') { const {user_id,course_id,days}=body; if(!user_id||!course_id||!days) return err('All fields required'); const expires=new Date(Date.now()+days*86400000).toISOString(); await db.prepare('INSERT OR REPLACE INTO memberships (user_id,course_id,expires_at,granted_by) VALUES (?,?,?,?)').bind(user_id,course_id,expires,user.id).run(); return json({message:'Granted',expires_at:expires},201); }
  if(method==='PUT' && path.match(/^\/memberships\/\d+\/extend$/)) { const {days}=body; await db.prepare(`UPDATE memberships SET expires_at=datetime(expires_at,'+'||?||' days'), is_active=1 WHERE id=?`).bind(days, parseInt(path.split('/')[2])).run(); return json({message:'Extended'}); }
  if(method==='PUT' && path.match(/^\/memberships\/\d+\/cancel$/)) { await db.prepare('UPDATE memberships SET is_active=0 WHERE id=?').bind(parseInt(path.split('/')[2])).run(); return json({message:'Cancelled'}); }

  return err('Route not found', 404);
}

// ═══ MAIN ═══
export async function onRequest(context) {
  const {request, env} = context;
  const db = env.ABHYUDOY_DB;
  if(request.method==='OPTIONS') return new Response(null, {headers:CORS});
  await ensureTables(db);
  const url = new URL(request.url);
  const fullPath = url.pathname.replace(/^\/api/, '');
  let body = {};
  if(['POST','PUT','DELETE'].includes(request.method)) try { body = await request.json(); } catch {}
  const authUser = await getUser(request);
  if(fullPath.startsWith('/auth/')) return handleAuth(request.method, fullPath.replace('/auth',''), body, db);
  if(fullPath.startsWith('/user/')) return handleUser(request.method, fullPath.replace('/user',''), body, db, authUser);
  if(fullPath.startsWith('/admin/')) return handleAdmin(request.method, fullPath.replace('/admin',''), body, db, authUser);
  return err('API route not found', 404);
}
