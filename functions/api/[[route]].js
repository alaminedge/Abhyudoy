// functions/api/[[route]].js
// Abhyudoy EdTech Platform - Complete Working API
// Handles ALL admin and user routes

export async function onRequest(context) {
  const { request, env } = context;
  
  // CORS headers for all responses
  const corsHeaders = {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization'
  };
  
  // Handle CORS preflight requests
  if (request.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }
  
  // Parse URL and path
  const url = new URL(request.url);
  const path = url.pathname;
  
  // Parse request body for POST and PUT
  let body = {};
  if (request.method === 'POST' || request.method === 'PUT') {
    try {
      const contentType = request.headers.get('Content-Type') || '';
      if (contentType.includes('application/json')) {
        body = await request.json();
      }
    } catch (error) {
      console.error('Error parsing request body:', error.message);
    }
  }
  
  // Helper function to send JSON response
  function sendJSON(data, status) {
    status = status || 200;
    return new Response(JSON.stringify(data), {
      status: status,
      headers: corsHeaders
    });
  }
  
  // Helper function to send error response
  function sendError(message, status) {
    status = status || 400;
    return sendJSON({ error: message }, status);
  }
  
  // Get database connection
  const db = env.ABHYUDOY_DB;
  
  console.log('Request:', request.method, path);
  
  // ==========================================
  // DATABASE MIGRATION - Run once per cold start
  // ==========================================
  if (db && !globalThis.__abhyudoy_migrated) {
    console.log('Running database migration...');
    
    try {
      // Create tables if they don't exist (fresh database)
      await db.prepare(`
        CREATE TABLE IF NOT EXISTS courses (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          title TEXT NOT NULL,
          description TEXT DEFAULT '',
          thumbnail TEXT,
          is_active INTEGER DEFAULT 1,
          show_in_browse INTEGER DEFAULT 0,
          subject_area TEXT,
          difficulty_level TEXT,
          enrollment_type TEXT DEFAULT 'open',
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
      `).run();
      
      await db.prepare(`
        CREATE TABLE IF NOT EXISTS subjects (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          course_id INTEGER NOT NULL,
          name TEXT NOT NULL,
          has_papers INTEGER DEFAULT 1,
          sort_order INTEGER DEFAULT 0,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
      `).run();
      
      await db.prepare(`
        CREATE TABLE IF NOT EXISTS papers (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          subject_id INTEGER NOT NULL,
          name TEXT NOT NULL,
          sort_order INTEGER DEFAULT 0,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
      `).run();
      
      await db.prepare(`
        CREATE TABLE IF NOT EXISTS chapters (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          paper_id INTEGER NOT NULL,
          title TEXT NOT NULL,
          sort_order INTEGER DEFAULT 0,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
      `).run();
      
      await db.prepare(`
        CREATE TABLE IF NOT EXISTS lectures (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          chapter_id INTEGER NOT NULL,
          title TEXT NOT NULL,
          yt_video_id TEXT NOT NULL,
          sort_order INTEGER DEFAULT 0,
          description TEXT DEFAULT '',
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
      `).run();
      
      await db.prepare(`
        CREATE TABLE IF NOT EXISTS lecture_pdfs (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          lecture_id INTEGER NOT NULL,
          title TEXT NOT NULL,
          pdf_url TEXT NOT NULL,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
      `).run();
      
      await db.prepare(`
        CREATE TABLE IF NOT EXISTS resources (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          course_id INTEGER NOT NULL,
          title TEXT NOT NULL,
          pdf_url TEXT NOT NULL,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
      `).run();
      
      await db.prepare(`
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL,
          email TEXT UNIQUE NOT NULL,
          password TEXT NOT NULL,
          role TEXT DEFAULT 'user',
          is_approved INTEGER DEFAULT 0,
          is_blocked INTEGER DEFAULT 0,
          restriction_override INTEGER DEFAULT 0,
          phone TEXT,
          institution TEXT,
          name_last_changed DATETIME,
          email_last_changed DATETIME,
          password_last_changed DATETIME,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
      `).run();
      
      await db.prepare(`
        CREATE TABLE IF NOT EXISTS memberships (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL,
          course_id INTEGER NOT NULL,
          expires_at DATETIME NOT NULL,
          is_active INTEGER DEFAULT 1,
          granted_by INTEGER,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          UNIQUE(user_id, course_id)
        )
      `).run();
      
      await db.prepare(`
        CREATE TABLE IF NOT EXISTS enrollment_requests (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL,
          course_id INTEGER NOT NULL,
          status TEXT DEFAULT 'pending',
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          UNIQUE(user_id, course_id)
        )
      `).run();
      
      await db.prepare(`
        CREATE TABLE IF NOT EXISTS notifications (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          title TEXT NOT NULL,
          message TEXT,
          type TEXT DEFAULT 'info',
          target_type TEXT DEFAULT 'all',
          target_id INTEGER,
          action_url TEXT,
          is_active INTEGER DEFAULT 1,
          scheduled_at DATETIME,
          expires_at DATETIME,
          created_by INTEGER,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
      `).run();
      
      await db.prepare(`
        CREATE TABLE IF NOT EXISTS notification_reads (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          notification_id INTEGER NOT NULL,
          user_id INTEGER NOT NULL,
          read_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          UNIQUE(notification_id, user_id)
        )
      `).run();
      
      await db.prepare(`
        CREATE TABLE IF NOT EXISTS support_tickets (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL,
          email TEXT NOT NULL,
          subject TEXT,
          message TEXT NOT NULL,
          status TEXT DEFAULT 'open',
          user_id INTEGER,
          resolved_at DATETIME,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
      `).run();
      
      await db.prepare(`
        CREATE TABLE IF NOT EXISTS updates (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          version TEXT,
          title TEXT NOT NULL,
          type TEXT DEFAULT 'feature',
          changelog TEXT,
          show_popup INTEGER DEFAULT 1,
          dismissible INTEGER DEFAULT 1,
          status TEXT DEFAULT 'draft',
          release_date DATETIME,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
      `).run();
      
      await db.prepare(`
        CREATE TABLE IF NOT EXISTS update_seen (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          update_id INTEGER NOT NULL,
          user_id INTEGER NOT NULL,
          seen_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          UNIQUE(update_id, user_id)
        )
      `).run();
      
      // Add missing columns to existing tables (for old databases)
      try {
        await db.prepare(`ALTER TABLE courses ADD COLUMN show_in_browse INTEGER DEFAULT 0`).run();
      } catch (e) {
        // Column already exists, ignore
      }
      
      try {
        await db.prepare(`ALTER TABLE courses ADD COLUMN subject_area TEXT`).run();
      } catch (e) {
        // Column already exists, ignore
      }
      
      try {
        await db.prepare(`ALTER TABLE courses ADD COLUMN difficulty_level TEXT`).run();
      } catch (e) {
        // Column already exists, ignore
      }
      
      try {
        await db.prepare(`ALTER TABLE courses ADD COLUMN enrollment_type TEXT DEFAULT 'open'`).run();
      } catch (e) {
        // Column already exists, ignore
      }
      
      try {
        await db.prepare(`ALTER TABLE courses ADD COLUMN updated_at DATETIME DEFAULT CURRENT_TIMESTAMP`).run();
      } catch (e) {
        // Column already exists, ignore
      }
      
      try {
        await db.prepare(`ALTER TABLE users ADD COLUMN phone TEXT`).run();
      } catch (e) {
        // Column already exists, ignore
      }
      
      try {
        await db.prepare(`ALTER TABLE users ADD COLUMN institution TEXT`).run();
      } catch (e) {
        // Column already exists, ignore
      }
      
      try {
        await db.prepare(`ALTER TABLE users ADD COLUMN name_last_changed DATETIME`).run();
      } catch (e) {
        // Column already exists, ignore
      }
      
      try {
        await db.prepare(`ALTER TABLE users ADD COLUMN email_last_changed DATETIME`).run();
      } catch (e) {
        // Column already exists, ignore
      }
      
      try {
        await db.prepare(`ALTER TABLE users ADD COLUMN password_last_changed DATETIME`).run();
      } catch (e) {
        // Column already exists, ignore
      }
      
      try {
        await db.prepare(`ALTER TABLE users ADD COLUMN restriction_override INTEGER DEFAULT 0`).run();
      } catch (e) {
        // Column already exists, ignore
      }
      
      try {
        await db.prepare(`ALTER TABLE notifications ADD COLUMN target_id INTEGER`).run();
      } catch (e) {
        // Column already exists, ignore
      }
      
      try {
        await db.prepare(`ALTER TABLE notifications ADD COLUMN action_url TEXT`).run();
      } catch (e) {
        // Column already exists, ignore
      }
      
      try {
        await db.prepare(`ALTER TABLE notifications ADD COLUMN scheduled_at DATETIME`).run();
      } catch (e) {
        // Column already exists, ignore
      }
      
      try {
        await db.prepare(`ALTER TABLE notifications ADD COLUMN expires_at DATETIME`).run();
      } catch (e) {
        // Column already exists, ignore
      }
      
      try {
        await db.prepare(`ALTER TABLE notifications ADD COLUMN created_by INTEGER`).run();
      } catch (e) {
        // Column already exists, ignore
      }
      
      // Create default admin user
      try {
        await db.prepare(`
          INSERT OR IGNORE INTO users (name, email, password, role, is_approved)
          VALUES ('Admin', 'cnct.nx@gmail.com', 'admin123_hashed', 'admin', 1)
        `).run();
      } catch (e) {
        console.error('Admin user creation error:', e.message);
      }
      
      console.log('Database migration complete');
      globalThis.__abhyudoy_migrated = true;
      
    } catch (error) {
      console.error('Migration error:', error.message);
    }
  }
  
  // ==========================================
  // AUTH ROUTES
  // ==========================================
  
  // POST /api/auth/login
  if (path === '/api/auth/login' && request.method === 'POST') {
    const { email, password } = body;
    
    // Simple login for testing
    if (email === 'cnct.nx@gmail.com' && password === 'admin123') {
      return sendJSON({
        token: 'abhyudoy_admin_token_2024',
        user: {
          id: 1,
          name: 'Admin',
          email: 'cnct.nx@gmail.com',
          role: 'admin'
        }
      });
    }
    
    // If database exists, check credentials
    if (db) {
      try {
        const user = await db.prepare(
          'SELECT * FROM users WHERE email = ? AND is_approved = 1 AND is_blocked = 0'
        ).bind(email.toLowerCase().trim()).first();
        
        if (user) {
          return sendJSON({
            token: 'abhyudoy_token_' + user.id + '_' + Date.now(),
            user: {
              id: user.id,
              name: user.name,
              email: user.email,
              role: user.role
            }
          });
        }
      } catch (e) {
        console.error('Login error:', e.message);
      }
    }
    
    return sendError('Invalid email or password', 401);
  }
  
  // POST /api/auth/signup
  if (path === '/api/auth/signup' && request.method === 'POST') {
    const { name, email, password, device_fingerprint } = body;
    
    if (!name || !email || !password) {
      return sendError('All fields are required');
    }
    
    if (password.length < 6) {
      return sendError('Password must be at least 6 characters');
    }
    
    if (!db) {
      return sendJSON({ message: 'Account created! Awaiting approval.' }, 201);
    }
    
    try {
      // Check if email already exists
      const existing = await db.prepare(
        'SELECT id FROM users WHERE email = ?'
      ).bind(email.toLowerCase().trim()).first();
      
      if (existing) {
        return sendError('Email already registered');
      }
      
      // Check device fingerprint
      if (device_fingerprint) {
        const deviceExists = await db.prepare(
          'SELECT COUNT(*) as count FROM device_registrations WHERE device_fingerprint = ?'
        ).bind(device_fingerprint).first();
        
        if (deviceExists && deviceExists.count > 0) {
          return sendError('An account already exists on this device', 403);
        }
      }
      
      // Create user
      const result = await db.prepare(
        'INSERT INTO users (name, email, password) VALUES (?, ?, ?)'
      ).bind(name.trim(), email.toLowerCase().trim(), password).run();
      
      // Save device fingerprint
      if (device_fingerprint) {
        await db.prepare(
          'INSERT INTO device_registrations (device_fingerprint, user_id) VALUES (?, ?)'
        ).bind(device_fingerprint, result.meta.last_row_id).run();
      }
      
      return sendJSON({ message: 'Account created! Awaiting admin approval.' }, 201);
      
    } catch (e) {
      console.error('Signup error:', e.message);
      return sendError('Signup failed. Please try again.');
    }
  }
  
  // ==========================================
  // CONTACT ROUTE (Public)
  // ==========================================
  
  if (path === '/api/contact' && request.method === 'POST') {
    const { name, email, subject, message } = body;
    
    if (!name || !email || !message) {
      return sendError('Name, email, and message are required');
    }
    
    if (db) {
      try {
        await db.prepare(
          'INSERT INTO support_tickets (name, email, subject, message) VALUES (?, ?, ?, ?)'
        ).bind(name, email, subject || 'General Inquiry', message).run();
      } catch (e) {
        console.error('Contact error:', e.message);
      }
    }
    
    return sendJSON({ message: 'Message received! We will respond within 24 hours.' }, 201);
  }
  
  // ==========================================
  // ADMIN ROUTES
  // ==========================================
  
  if (path.startsWith('/api/admin/')) {
    
    // ──────────────────────────────────────
    // COURSES
    // ──────────────────────────────────────
    
    // GET /api/admin/courses
    if (path === '/api/admin/courses' && request.method === 'GET') {
      if (!db) {
        return sendJSON([]);
      }
      
      try {
        const result = await db.prepare(
          'SELECT * FROM courses ORDER BY id DESC'
        ).all();
        
        return sendJSON(result.results || []);
      } catch (e) {
        console.error('Get courses error:', e.message);
        return sendJSON([]);
      }
    }
    
    // POST /api/admin/courses
    if (path === '/api/admin/courses' && request.method === 'POST') {
      const { title, description, thumbnail, is_active, show_in_browse, subject_area, difficulty_level, enrollment_type } = body;
      
      if (!title) {
        return sendError('Title is required');
      }
      
      if (!db) {
        return sendJSON({ id: Date.now(), message: 'Course created (test mode)' }, 201);
      }
      
      try {
        const result = await db.prepare(`
          INSERT INTO courses (title, description, thumbnail, is_active, show_in_browse, subject_area, difficulty_level, enrollment_type)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
          title,
          description || '',
          thumbnail || null,
          is_active !== undefined ? is_active : 1,
          show_in_browse ? 1 : 0,
          subject_area || null,
          difficulty_level || null,
          enrollment_type || 'open'
        ).run();
        
        return sendJSON({
          id: result.meta.last_row_id,
          message: 'Course created successfully'
        }, 201);
        
      } catch (e) {
        console.error('Create course error:', e.message);
        return sendError('Failed to create course: ' + e.message, 500);
      }
    }
    
    // PUT /api/admin/courses/:id
    if (request.method === 'PUT' && path.match(/^\/api\/admin\/courses\/\d+$/)) {
      const courseId = parseInt(path.split('/')[4]);
      const { title, description, thumbnail, is_active, show_in_browse, subject_area, difficulty_level, enrollment_type } = body;
      
      if (!db) {
        return sendJSON({ message: 'Course updated (test mode)' });
      }
      
      try {
        const updates = [];
        const values = [];
        
        if (title !== undefined) {
          updates.push('title = ?');
          values.push(title);
        }
        if (description !== undefined) {
          updates.push('description = ?');
          values.push(description);
        }
        if (thumbnail !== undefined) {
          updates.push('thumbnail = ?');
          values.push(thumbnail);
        }
        if (is_active !== undefined) {
          updates.push('is_active = ?');
          values.push(is_active);
        }
        if (show_in_browse !== undefined) {
          updates.push('show_in_browse = ?');
          values.push(show_in_browse ? 1 : 0);
        }
        if (subject_area !== undefined) {
          updates.push('subject_area = ?');
          values.push(subject_area);
        }
        if (difficulty_level !== undefined) {
          updates.push('difficulty_level = ?');
          values.push(difficulty_level);
        }
        if (enrollment_type !== undefined) {
          updates.push('enrollment_type = ?');
          values.push(enrollment_type);
        }
        
        if (updates.length > 0) {
          updates.push('updated_at = CURRENT_TIMESTAMP');
          values.push(courseId);
          
          await db.prepare(
            `UPDATE courses SET ${updates.join(', ')} WHERE id = ?`
          ).bind(...values).run();
        }
        
        return sendJSON({ message: 'Course updated successfully' });
        
      } catch (e) {
        console.error('Update course error:', e.message);
        return sendError('Failed to update course: ' + e.message, 500);
      }
    }
    
    // DELETE /api/admin/courses/:id
    if (request.method === 'DELETE' && path.match(/^\/api\/admin\/courses\/\d+$/)) {
      const courseId = parseInt(path.split('/')[4]);
      
      if (db) {
        try {
          // Delete related records
          await db.prepare('DELETE FROM memberships WHERE course_id = ?').bind(courseId).run();
          await db.prepare('DELETE FROM enrollment_requests WHERE course_id = ?').bind(courseId).run();
          await db.prepare('DELETE FROM resources WHERE course_id = ?').bind(courseId).run();
          
          // Delete subjects and their children
          const subjects = await db.prepare('SELECT id FROM subjects WHERE course_id = ?').bind(courseId).all();
          for (const subject of (subjects.results || [])) {
            const papers = await db.prepare('SELECT id FROM papers WHERE subject_id = ?').bind(subject.id).all();
            for (const paper of (papers.results || [])) {
              const chapters = await db.prepare('SELECT id FROM chapters WHERE paper_id = ?').bind(paper.id).all();
              for (const chapter of (chapters.results || [])) {
                await db.prepare('DELETE FROM lecture_pdfs WHERE lecture_id IN (SELECT id FROM lectures WHERE chapter_id = ?)').bind(chapter.id).run();
                await db.prepare('DELETE FROM lectures WHERE chapter_id = ?').bind(chapter.id).run();
              }
              await db.prepare('DELETE FROM chapters WHERE paper_id = ?').bind(paper.id).run();
            }
            await db.prepare('DELETE FROM papers WHERE subject_id = ?').bind(subject.id).run();
          }
          await db.prepare('DELETE FROM subjects WHERE course_id = ?').bind(courseId).run();
          
          // Delete course
          await db.prepare('DELETE FROM courses WHERE id = ?').bind(courseId).run();
        } catch (e) {
          console.error('Delete course error:', e.message);
          return sendError('Failed to delete course: ' + e.message, 500);
        }
      }
      
      return sendJSON({ message: 'Course deleted successfully' });
    }
    
    // ──────────────────────────────────────
    // SUBJECTS
    // ──────────────────────────────────────
    
    // GET /api/admin/all-subjects
    if (path === '/api/admin/all-subjects' && request.method === 'GET') {
      if (!db) return sendJSON([]);
      
      try {
        const result = await db.prepare('SELECT * FROM subjects ORDER BY course_id ASC, sort_order ASC').all();
        return sendJSON(result.results || []);
      } catch (e) {
        return sendJSON([]);
      }
    }
    
    // POST /api/admin/subjects
    if (path === '/api/admin/subjects' && request.method === 'POST') {
      const { course_id, name, has_papers } = body;
      
      if (!course_id || !name) {
        return sendError('Course ID and name are required');
      }
      
      if (!db) {
        return sendJSON({ id: Date.now(), message: 'Subject created (test mode)' }, 201);
      }
      
      try {
        const result = await db.prepare(
          'INSERT INTO subjects (course_id, name, has_papers) VALUES (?, ?, ?)'
        ).bind(course_id, name, has_papers !== undefined ? has_papers : 1).run();
        
        // If no papers, create a default paper
        if (!has_papers || has_papers === 0) {
          await db.prepare(
            'INSERT INTO papers (subject_id, name, sort_order) VALUES (?, ?, 0)'
          ).bind(result.meta.last_row_id, 'Full Course').run();
        }
        
        return sendJSON({ id: result.meta.last_row_id, message: 'Subject created' }, 201);
      } catch (e) {
        return sendError('Failed to create subject: ' + e.message, 500);
      }
    }
    
    // DELETE /api/admin/subjects/:id
    if (request.method === 'DELETE' && path.match(/^\/api\/admin\/subjects\/\d+$/)) {
      const subjectId = parseInt(path.split('/')[4]);
      
      if (db) {
        try {
          const papers = await db.prepare('SELECT id FROM papers WHERE subject_id = ?').bind(subjectId).all();
          for (const paper of (papers.results || [])) {
            const chapters = await db.prepare('SELECT id FROM chapters WHERE paper_id = ?').bind(paper.id).all();
            for (const chapter of (chapters.results || [])) {
              await db.prepare('DELETE FROM lecture_pdfs WHERE lecture_id IN (SELECT id FROM lectures WHERE chapter_id = ?)').bind(chapter.id).run();
              await db.prepare('DELETE FROM lectures WHERE chapter_id = ?').bind(chapter.id).run();
            }
            await db.prepare('DELETE FROM chapters WHERE paper_id = ?').bind(paper.id).run();
          }
          await db.prepare('DELETE FROM papers WHERE subject_id = ?').bind(subjectId).run();
          await db.prepare('DELETE FROM subjects WHERE id = ?').bind(subjectId).run();
        } catch (e) {
          return sendError('Failed to delete subject: ' + e.message, 500);
        }
      }
      
      return sendJSON({ message: 'Subject deleted' });
    }
    
    // ──────────────────────────────────────
    // PAPERS
    // ──────────────────────────────────────
    
    // GET /api/admin/all-papers
    if (path === '/api/admin/all-papers' && request.method === 'GET') {
      if (!db) return sendJSON([]);
      
      try {
        const result = await db.prepare('SELECT * FROM papers ORDER BY subject_id ASC, sort_order ASC').all();
        return sendJSON(result.results || []);
      } catch (e) {
        return sendJSON([]);
      }
    }
    
    // POST /api/admin/papers
    if (path === '/api/admin/papers' && request.method === 'POST') {
      const { subject_id, name } = body;
      
      if (!subject_id || !name) {
        return sendError('Subject ID and name are required');
      }
      
      if (!db) {
        return sendJSON({ id: Date.now(), message: 'Paper created (test mode)' }, 201);
      }
      
      try {
        const result = await db.prepare(
          'INSERT INTO papers (subject_id, name) VALUES (?, ?)'
        ).bind(subject_id, name).run();
        
        return sendJSON({ id: result.meta.last_row_id, message: 'Paper created' }, 201);
      } catch (e) {
        return sendError('Failed to create paper: ' + e.message, 500);
      }
    }
    
    // DELETE /api/admin/papers/:id
    if (request.method === 'DELETE' && path.match(/^\/api\/admin\/papers\/\d+$/)) {
      const paperId = parseInt(path.split('/')[4]);
      
      if (db) {
        try {
          const chapters = await db.prepare('SELECT id FROM chapters WHERE paper_id = ?').bind(paperId).all();
          for (const chapter of (chapters.results || [])) {
            await db.prepare('DELETE FROM lecture_pdfs WHERE lecture_id IN (SELECT id FROM lectures WHERE chapter_id = ?)').bind(chapter.id).run();
            await db.prepare('DELETE FROM lectures WHERE chapter_id = ?').bind(chapter.id).run();
          }
          await db.prepare('DELETE FROM chapters WHERE paper_id = ?').bind(paperId).run();
          await db.prepare('DELETE FROM papers WHERE id = ?').bind(paperId).run();
        } catch (e) {
          return sendError('Failed to delete paper: ' + e.message, 500);
        }
      }
      
      return sendJSON({ message: 'Paper deleted' });
    }
    
    // ──────────────────────────────────────
    // CHAPTERS
    // ──────────────────────────────────────
    
    // GET /api/admin/all-chapters
    if (path === '/api/admin/all-chapters' && request.method === 'GET') {
      if (!db) return sendJSON([]);
      
      try {
        const result = await db.prepare('SELECT * FROM chapters ORDER BY paper_id ASC, sort_order ASC').all();
        return sendJSON(result.results || []);
      } catch (e) {
        return sendJSON([]);
      }
    }
    
    // POST /api/admin/chapters
    if (path === '/api/admin/chapters' && request.method === 'POST') {
      const { paper_id, title, sort_order } = body;
      
      if (!paper_id || !title) {
        return sendError('Paper ID and title are required');
      }
      
      if (!db) {
        return sendJSON({ id: Date.now(), message: 'Chapter created (test mode)' }, 201);
      }
      
      try {
        const result = await db.prepare(
          'INSERT INTO chapters (paper_id, title, sort_order) VALUES (?, ?, ?)'
        ).bind(paper_id, title, sort_order || 0).run();
        
        return sendJSON({ id: result.meta.last_row_id, message: 'Chapter created' }, 201);
      } catch (e) {
        return sendError('Failed to create chapter: ' + e.message, 500);
      }
    }
    
    // DELETE /api/admin/chapters/:id
    if (request.method === 'DELETE' && path.match(/^\/api\/admin\/chapters\/\d+$/)) {
      const chapterId = parseInt(path.split('/')[4]);
      
      if (db) {
        try {
          await db.prepare('DELETE FROM lecture_pdfs WHERE lecture_id IN (SELECT id FROM lectures WHERE chapter_id = ?)').bind(chapterId).run();
          await db.prepare('DELETE FROM lectures WHERE chapter_id = ?').bind(chapterId).run();
          await db.prepare('DELETE FROM chapters WHERE id = ?').bind(chapterId).run();
        } catch (e) {
          return sendError('Failed to delete chapter: ' + e.message, 500);
        }
      }
      
      return sendJSON({ message: 'Chapter deleted' });
    }
    
    // ──────────────────────────────────────
    // LECTURES
    // ──────────────────────────────────────
    
    // GET /api/admin/all-lectures
    if (path === '/api/admin/all-lectures' && request.method === 'GET') {
      if (!db) return sendJSON([]);
      
      try {
        const result = await db.prepare(`
          SELECT l.*, ch.title as chapter_title, p.name as paper_name, s.name as subject_name, s.course_id
          FROM lectures l
          LEFT JOIN chapters ch ON l.chapter_id = ch.id
          LEFT JOIN papers p ON ch.paper_id = p.id
          LEFT JOIN subjects s ON p.subject_id = s.id
          ORDER BY l.created_at DESC
        `).all();
        
        return sendJSON(result.results || []);
      } catch (e) {
        return sendJSON([]);
      }
    }
    
    // POST /api/admin/lectures
    if (path === '/api/admin/lectures' && request.method === 'POST') {
      const { chapter_id, title, yt_video_id, sort_order, description } = body;
      
      if (!chapter_id || !title || !yt_video_id) {
        return sendError('Chapter ID, title, and YouTube ID are required');
      }
      
      if (!db) {
        return sendJSON({ id: Date.now(), message: 'Lecture created (test mode)' }, 201);
      }
      
      try {
        const result = await db.prepare(
          'INSERT INTO lectures (chapter_id, title, yt_video_id, sort_order, description) VALUES (?, ?, ?, ?, ?)'
        ).bind(chapter_id, title, yt_video_id, sort_order || 0, description || '').run();
        
        return sendJSON({ id: result.meta.last_row_id, message: 'Lecture created' }, 201);
      } catch (e) {
        return sendError('Failed to create lecture: ' + e.message, 500);
      }
    }
    
    // PUT /api/admin/lectures/:id
    if (request.method === 'PUT' && path.match(/^\/api\/admin\/lectures\/\d+$/)) {
      const lectureId = parseInt(path.split('/')[4]);
      const { title, yt_video_id, sort_order, description } = body;
      
      if (!db) return sendJSON({ message: 'Lecture updated (test mode)' });
      
      try {
        const updates = [];
        const values = [];
        
        if (title !== undefined) { updates.push('title = ?'); values.push(title); }
        if (yt_video_id !== undefined) { updates.push('yt_video_id = ?'); values.push(yt_video_id); }
        if (sort_order !== undefined) { updates.push('sort_order = ?'); values.push(sort_order); }
        if (description !== undefined) { updates.push('description = ?'); values.push(description); }
        
        if (updates.length > 0) {
          updates.push('updated_at = CURRENT_TIMESTAMP');
          values.push(lectureId);
          await db.prepare(`UPDATE lectures SET ${updates.join(', ')} WHERE id = ?`).bind(...values).run();
        }
        
        return sendJSON({ message: 'Lecture updated' });
      } catch (e) {
        return sendError('Failed to update lecture: ' + e.message, 500);
      }
    }
    
    // DELETE /api/admin/lectures/:id
    if (request.method === 'DELETE' && path.match(/^\/api\/admin\/lectures\/\d+$/)) {
      const lectureId = parseInt(path.split('/')[4]);
      
      if (db) {
        try {
          await db.prepare('DELETE FROM lecture_pdfs WHERE lecture_id = ?').bind(lectureId).run();
          await db.prepare('DELETE FROM lectures WHERE id = ?').bind(lectureId).run();
        } catch (e) {
          return sendError('Failed to delete lecture: ' + e.message, 500);
        }
      }
      
      return sendJSON({ message: 'Lecture deleted' });
    }
    
    // ──────────────────────────────────────
    // USERS
    // ──────────────────────────────────────
    
    // GET /api/admin/users
    if (path === '/api/admin/users' && request.method === 'GET') {
      if (!db) {
        return sendJSON([{
          id: 1,
          name: 'Admin',
          email: 'cnct.nx@gmail.com',
          role: 'admin',
          is_approved: 1,
          is_blocked: 0,
          restriction_override: 0,
          created_at: new Date().toISOString()
        }]);
      }
      
      try {
        const result = await db.prepare(
          'SELECT id, name, email, role, is_blocked, is_approved, restriction_override, created_at FROM users ORDER BY created_at DESC'
        ).all();
        
        return sendJSON(result.results || []);
      } catch (e) {
        return sendJSON([]);
      }
    }
    
    // PUT /api/admin/users/:id/approve
    if (request.method === 'PUT' && path.match(/^\/api\/admin\/users\/\d+\/approve$/)) {
      const userId = parseInt(path.split('/')[4]);
      
      if (db) {
        try {
          await db.prepare('UPDATE users SET is_approved = 1 WHERE id = ?').bind(userId).run();
        } catch (e) {
          return sendError('Failed to approve user: ' + e.message, 500);
        }
      }
      
      return sendJSON({ message: 'User approved' });
    }
    
    // PUT /api/admin/users/:id/block
    if (request.method === 'PUT' && path.match(/^\/api\/admin\/users\/\d+\/block$/)) {
      const userId = parseInt(path.split('/')[4]);
      const { is_blocked } = body;
      
      if (db) {
        try {
          await db.prepare('UPDATE users SET is_blocked = ? WHERE id = ?')
            .bind(is_blocked ? 1 : 0, userId).run();
        } catch (e) {
          return sendError('Failed to update user: ' + e.message, 500);
        }
      }
      
      return sendJSON({ message: is_blocked ? 'User blocked' : 'User unblocked' });
    }
    
    // PUT /api/admin/users/:id/override-restriction
    if (request.method === 'PUT' && path.match(/^\/api\/admin\/users\/\d+\/override-restriction$/)) {
      const userId = parseInt(path.split('/')[4]);
      const { override } = body;
      
      if (db) {
        try {
          await db.prepare('UPDATE users SET restriction_override = ? WHERE id = ?')
            .bind(override ? 1 : 0, userId).run();
        } catch (e) {
          return sendError('Failed to update restriction: ' + e.message, 500);
        }
      }
      
      return sendJSON({ message: override ? 'Restriction override enabled' : 'Restriction override disabled' });
    }
    
    // DELETE /api/admin/users/:id
    if (request.method === 'DELETE' && path.match(/^\/api\/admin\/users\/\d+$/)) {
      const userId = parseInt(path.split('/')[4]);
      
      if (db) {
        try {
          await db.prepare('DELETE FROM memberships WHERE user_id = ?').bind(userId).run();
          await db.prepare('DELETE FROM device_registrations WHERE user_id = ?').bind(userId).run();
          await db.prepare('DELETE FROM notification_reads WHERE user_id = ?').bind(userId).run();
          await db.prepare('DELETE FROM enrollment_requests WHERE user_id = ?').bind(userId).run();
          await db.prepare("DELETE FROM users WHERE id = ? AND role != 'admin'").bind(userId).run();
        } catch (e) {
          return sendError('Failed to delete user: ' + e.message, 500);
        }
      }
      
      return sendJSON({ message: 'User deleted' });
    }
    
    // ──────────────────────────────────────
    // MEMBERSHIPS
    // ──────────────────────────────────────
    
    // GET /api/admin/memberships
    if (path === '/api/admin/memberships' && request.method === 'GET') {
      if (!db) return sendJSON([]);
      
      try {
        const result = await db.prepare(`
          SELECT m.*, u.name as user_name, u.email as user_email, c.title as course_title
          FROM memberships m
          LEFT JOIN users u ON m.user_id = u.id
          LEFT JOIN courses c ON m.course_id = c.id
          ORDER BY m.created_at DESC
        `).all();
        
        return sendJSON(result.results || []);
      } catch (e) {
        return sendJSON([]);
      }
    }
    
    // POST /api/admin/memberships
    if (path === '/api/admin/memberships' && request.method === 'POST') {
      const { user_id, course_id, days } = body;
      
      if (!user_id || !course_id || !days) {
        return sendError('User ID, course ID, and days are required');
      }
      
      if (!db) {
        const expires_at = new Date(Date.now() + days * 86400000).toISOString();
        return sendJSON({ message: 'Membership granted (test mode)', expires_at: expires_at }, 201);
      }
      
      try {
        const expires_at = new Date(Date.now() + days * 86400000).toISOString();
        
        await db.prepare(
          'INSERT OR REPLACE INTO memberships (user_id, course_id, expires_at, is_active) VALUES (?, ?, ?, 1)'
        ).bind(user_id, course_id, expires_at).run();
        
        return sendJSON({ message: 'Membership granted', expires_at: expires_at }, 201);
      } catch (e) {
        return sendError('Failed to grant membership: ' + e.message, 500);
      }
    }
    
    // PUT /api/admin/memberships/:id/extend
    if (request.method === 'PUT' && path.match(/^\/api\/admin\/memberships\/\d+\/extend$/)) {
      const membershipId = parseInt(path.split('/')[4]);
      const { days } = body;
      
      if (!days) return sendError('Days is required');
      
      if (db) {
        try {
          await db.prepare(
            `UPDATE memberships SET expires_at = datetime(expires_at, '+' || ? || ' days'), is_active = 1 WHERE id = ?`
          ).bind(days, membershipId).run();
        } catch (e) {
          return sendError('Failed to extend membership: ' + e.message, 500);
        }
      }
      
      return sendJSON({ message: 'Membership extended' });
    }
    
    // PUT /api/admin/memberships/:id/cancel
    if (request.method === 'PUT' && path.match(/^\/api\/admin\/memberships\/\d+\/cancel$/)) {
      const membershipId = parseInt(path.split('/')[4]);
      
      if (db) {
        try {
          await db.prepare('UPDATE memberships SET is_active = 0 WHERE id = ?').bind(membershipId).run();
        } catch (e) {
          return sendError('Failed to cancel membership: ' + e.message, 500);
        }
      }
      
      return sendJSON({ message: 'Membership cancelled' });
    }
    
    // ──────────────────────────────────────
    // ENROLLMENT REQUESTS
    // ──────────────────────────────────────
    
    // GET /api/admin/enrollment-requests
    if (path === '/api/admin/enrollment-requests' && request.method === 'GET') {
      if (!db) return sendJSON([]);
      
      try {
        const result = await db.prepare(`
          SELECT er.*, u.name as user_name, u.email as user_email, c.title as course_title
          FROM enrollment_requests er
          LEFT JOIN users u ON er.user_id = u.id
          LEFT JOIN courses c ON er.course_id = c.id
          ORDER BY er.created_at DESC
        `).all();
        
        return sendJSON(result.results || []);
      } catch (e) {
        return sendJSON([]);
      }
    }
    
    // PUT /api/admin/enrollment-requests/:id/approve
    if (request.method === 'PUT' && path.match(/^\/api\/admin\/enrollment-requests\/\d+\/approve$/)) {
      const requestId = parseInt(path.split('/')[4]);
      
      if (db) {
        try {
          const enrollmentRequest = await db.prepare(
            'SELECT * FROM enrollment_requests WHERE id = ?'
          ).bind(requestId).first();
          
          if (enrollmentRequest) {
            const expires_at = new Date(Date.now() + 365 * 86400000).toISOString();
            
            await db.prepare(
              'INSERT OR REPLACE INTO memberships (user_id, course_id, expires_at, is_active) VALUES (?, ?, ?, 1)'
            ).bind(enrollmentRequest.user_id, enrollmentRequest.course_id, expires_at).run();
            
            await db.prepare(
              "UPDATE enrollment_requests SET status = 'approved' WHERE id = ?"
            ).bind(requestId).run();
          }
        } catch (e) {
          return sendError('Failed to approve enrollment: ' + e.message, 500);
        }
      }
      
      return sendJSON({ message: 'Enrollment approved' });
    }
    
    // PUT /api/admin/enrollment-requests/:id/reject
    if (request.method === 'PUT' && path.match(/^\/api\/admin\/enrollment-requests\/\d+\/reject$/)) {
      const requestId = parseInt(path.split('/')[4]);
      
      if (db) {
        try {
          await db.prepare(
            "UPDATE enrollment_requests SET status = 'rejected' WHERE id = ?"
          ).bind(requestId).run();
        } catch (e) {
          return sendError('Failed to reject enrollment: ' + e.message, 500);
        }
      }
      
      return sendJSON({ message: 'Enrollment rejected' });
    }
    
    // ──────────────────────────────────────
    // NOTIFICATIONS
    // ──────────────────────────────────────
    
    // GET /api/admin/notifications
    if (path === '/api/admin/notifications' && request.method === 'GET') {
      if (!db) return sendJSON([]);
      
      try {
        const result = await db.prepare('SELECT * FROM notifications ORDER BY created_at DESC').all();
        return sendJSON(result.results || []);
      } catch (e) {
        return sendJSON([]);
      }
    }
    
    // POST /api/admin/notifications
    if (path === '/api/admin/notifications' && request.method === 'POST') {
      const { title, message, type, target_type, action_url, expires_at, is_active } = body;
      
      if (!title) return sendError('Title is required');
      
      if (!db) return sendJSON({ id: Date.now(), message: 'Notification created (test mode)' }, 201);
      
      try {
        const result = await db.prepare(
          'INSERT INTO notifications (title, message, type, target_type, action_url, expires_at, is_active) VALUES (?, ?, ?, ?, ?, ?, ?)'
        ).bind(
          title,
          message || '',
          type || 'info',
          target_type || 'all',
          action_url || null,
          expires_at || null,
          is_active !== undefined ? is_active : 1
        ).run();
        
        return sendJSON({ id: result.meta.last_row_id, message: 'Notification created' }, 201);
      } catch (e) {
        return sendError('Failed to create notification: ' + e.message, 500);
      }
    }
    
    // DELETE /api/admin/notifications/:id
    if (request.method === 'DELETE' && path.match(/^\/api\/admin\/notifications\/\d+$/)) {
      const notificationId = parseInt(path.split('/')[4]);
      
      if (db) {
        try {
          await db.prepare('DELETE FROM notification_reads WHERE notification_id = ?').bind(notificationId).run();
          await db.prepare('DELETE FROM notifications WHERE id = ?').bind(notificationId).run();
        } catch (e) {
          return sendError('Failed to delete notification: ' + e.message, 500);
        }
      }
      
      return sendJSON({ message: 'Notification deleted' });
    }
    
    // ──────────────────────────────────────
    // SUPPORT TICKETS
    // ──────────────────────────────────────
    
    // GET /api/admin/support-tickets
    if (path === '/api/admin/support-tickets' && request.method === 'GET') {
      if (!db) return sendJSON([]);
      
      try {
        const result = await db.prepare('SELECT * FROM support_tickets ORDER BY created_at DESC').all();
        return sendJSON(result.results || []);
      } catch (e) {
        return sendJSON([]);
      }
    }
    
    // PUT /api/admin/support-tickets/:id/resolve
    if (request.method === 'PUT' && path.match(/^\/api\/admin\/support-tickets\/\d+\/resolve$/)) {
      const ticketId = parseInt(path.split('/')[4]);
      
      if (db) {
        try {
          await db.prepare(
            "UPDATE support_tickets SET status = 'resolved', resolved_at = ? WHERE id = ?"
          ).bind(new Date().toISOString(), ticketId).run();
        } catch (e) {
          return sendError('Failed to resolve ticket: ' + e.message, 500);
        }
      }
      
      return sendJSON({ message: 'Ticket resolved' });
    }
    
    // ──────────────────────────────────────
    // UPDATES / CHANGELOG
    // ──────────────────────────────────────
    
    // GET /api/admin/updates
    if (path === '/api/admin/updates' && request.method === 'GET') {
      if (!db) return sendJSON([]);
      
      try {
        const result = await db.prepare('SELECT * FROM updates ORDER BY created_at DESC').all();
        return sendJSON(result.results || []);
      } catch (e) {
        return sendJSON([]);
      }
    }
    
    // POST /api/admin/updates
    if (path === '/api/admin/updates' && request.method === 'POST') {
      const { version, title, type, changelog, show_popup, dismissible, status, release_date } = body;
      
      if (!title) return sendError('Title is required');
      
      if (!db) return sendJSON({ id: Date.now(), message: 'Update created (test mode)' }, 201);
      
      try {
        const result = await db.prepare(
          'INSERT INTO updates (version, title, type, changelog, show_popup, dismissible, status, release_date) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
        ).bind(
          version || null,
          title,
          type || 'feature',
          changelog || '',
          show_popup !== undefined ? show_popup : 1,
          dismissible !== undefined ? dismissible : 1,
          status || 'draft',
          release_date || null
        ).run();
        
        return sendJSON({ id: result.meta.last_row_id, message: 'Update created' }, 201);
      } catch (e) {
        return sendError('Failed to create update: ' + e.message, 500);
      }
    }
    
    // PUT /api/admin/updates/:id
    if (request.method === 'PUT' && path.match(/^\/api\/admin\/updates\/\d+$/)) {
      const updateId = parseInt(path.split('/')[4]);
      const { title, status } = body;
      
      if (!db) return sendJSON({ message: 'Update saved (test mode)' });
      
      try {
        const updates = [];
        const values = [];
        
        if (title !== undefined) { updates.push('title = ?'); values.push(title); }
        if (status !== undefined) { updates.push('status = ?'); values.push(status); }
        
        if (updates.length > 0) {
          updates.push('updated_at = CURRENT_TIMESTAMP');
          values.push(updateId);
          await db.prepare(`UPDATE updates SET ${updates.join(', ')} WHERE id = ?`).bind(...values).run();
        }
        
        return sendJSON({ message: 'Update saved' });
      } catch (e) {
        return sendError('Failed to save update: ' + e.message, 500);
      }
    }
    
    // DELETE /api/admin/updates/:id
    if (request.method === 'DELETE' && path.match(/^\/api\/admin\/updates\/\d+$/)) {
      const updateId = parseInt(path.split('/')[4]);
      
      if (db) {
        try {
          await db.prepare('DELETE FROM update_seen WHERE update_id = ?').bind(updateId).run();
          await db.prepare('DELETE FROM updates WHERE id = ?').bind(updateId).run();
        } catch (e) {
          return sendError('Failed to delete update: ' + e.message, 500);
        }
      }
      
      return sendJSON({ message: 'Update deleted' });
    }
    
    // ──────────────────────────────────────
    // RESOURCES
    // ──────────────────────────────────────
    
    // GET /api/admin/resources/course/:id
    if (request.method === 'GET' && path.match(/^\/api\/admin\/resources\/course\/\d+$/)) {
      const courseId = parseInt(path.split('/')[5]);
      
      if (!db) return sendJSON([]);
      
      try {
        const result = await db.prepare(
          'SELECT * FROM resources WHERE course_id = ? ORDER BY created_at DESC'
        ).bind(courseId).all();
        
        return sendJSON(result.results || []);
      } catch (e) {
        return sendJSON([]);
      }
    }
    
    // POST /api/admin/resources
    if (path === '/api/admin/resources' && request.method === 'POST') {
      const { course_id, title, pdf_url } = body;
      
      if (!course_id || !title || !pdf_url) return sendError('All fields are required');
      
      if (!db) return sendJSON({ id: Date.now(), message: 'Resource added (test mode)' }, 201);
      
      try {
        const result = await db.prepare(
          'INSERT INTO resources (course_id, title, pdf_url) VALUES (?, ?, ?)'
        ).bind(course_id, title, pdf_url).run();
        
        return sendJSON({ id: result.meta.last_row_id, message: 'Resource added' }, 201);
      } catch (e) {
        return sendError('Failed to add resource: ' + e.message, 500);
      }
    }
    
    // DELETE /api/admin/resources/:id
    if (request.method === 'DELETE' && path.match(/^\/api\/admin\/resources\/\d+$/)) {
      const resourceId = parseInt(path.split('/')[4]);
      
      if (db) {
        try {
          await db.prepare('DELETE FROM resources WHERE id = ?').bind(resourceId).run();
        } catch (e) {
          return sendError('Failed to delete resource: ' + e.message, 500);
        }
      }
      
      return sendJSON({ message: 'Resource deleted' });
    }
    
    // ──────────────────────────────────────
    // LECTURE PDFs
    // ──────────────────────────────────────
    
    // POST /api/admin/lecture-pdfs
    if (path === '/api/admin/lecture-pdfs' && request.method === 'POST') {
      const { lecture_id, title, pdf_url } = body;
      
      if (!lecture_id || !title || !pdf_url) return sendError('All fields are required');
      
      if (!db) return sendJSON({ id: Date.now(), message: 'PDF added (test mode)' }, 201);
      
      try {
        const result = await db.prepare(
          'INSERT INTO lecture_pdfs (lecture_id, title, pdf_url) VALUES (?, ?, ?)'
        ).bind(lecture_id, title, pdf_url).run();
        
        return sendJSON({ id: result.meta.last_row_id, message: 'PDF added' }, 201);
      } catch (e) {
        return sendError('Failed to add PDF: ' + e.message, 500);
      }
    }
    
    // DELETE /api/admin/lecture-pdfs/:id
    if (request.method === 'DELETE' && path.match(/^\/api\/admin\/lecture-pdfs\/\d+$/)) {
      const pdfId = parseInt(path.split('/')[4]);
      
      if (db) {
        try {
          await db.prepare('DELETE FROM lecture_pdfs WHERE id = ?').bind(pdfId).run();
        } catch (e) {
          return sendError('Failed to delete PDF: ' + e.message, 500);
        }
      }
      
      return sendJSON({ message: 'PDF deleted' });
    }
  }
  
  // ==========================================
  // USER ROUTES
  // ==========================================
  
  if (path.startsWith('/api/user/')) {
    
    // GET /api/user/lecture/:id (for PDF modal in admin panel)
    if (request.method === 'GET' && path.match(/^\/api\/user\/lecture\/\d+$/)) {
      const lectureId = parseInt(path.split('/')[4]);
      
      if (!db) return sendJSON({ lecture: { id: lectureId }, pdfs: [] });
      
      try {
        const pdfs = await db.prepare(
          'SELECT * FROM lecture_pdfs WHERE lecture_id = ? ORDER BY created_at ASC'
        ).bind(lectureId).all();
        
        return sendJSON({
          lecture: { id: lectureId },
          pdfs: pdfs.results || []
        });
      } catch (e) {
        return sendJSON({ lecture: { id: lectureId }, pdfs: [] });
      }
    }
  }
  
  // ==========================================
  // 404 - Route not found
  // ==========================================
  
  console.log('Route not found:', path);
  return sendError('Route not found: ' + path, 404);
}
