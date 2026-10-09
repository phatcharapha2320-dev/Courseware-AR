-- 1. สร้างตารางพื้นฐาน
CREATE TABLE IF NOT EXISTS public.teachers (
    user_id UUID PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS public.students (
    id VARCHAR(11) PRIMARY KEY,
    title VARCHAR(20),
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    section VARCHAR(10),
    user_id UUID UNIQUE,
    photo_path TEXT
);

CREATE TABLE IF NOT EXISTS public.attempts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    kind VARCHAR(10) CHECK (kind IN ('pre', 'post')),
    score INTEGER NOT NULL,
    answers JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(user_id, kind)
);

CREATE TABLE IF NOT EXISTS public.progress (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    unit INTEGER NOT NULL,
    done BOOLEAN DEFAULT FALSE,
    UNIQUE(user_id, unit)
);

CREATE TABLE IF NOT EXISTS public.submissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    unit INTEGER NOT NULL,
    kind VARCHAR(10) CHECK (kind IN ('link', 'file')),
    url TEXT,
    storage_path TEXT,
    note TEXT,
    score INTEGER NULL,
    teacher_comment TEXT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.materials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title TEXT NOT NULL,
    kind VARCHAR(10) CHECK (kind IN ('file', 'link', 'video')),
    url TEXT,
    storage_path TEXT,
    file_name TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 2. ฟังก์ชันตรวจสอบสิทธิ์ผู้สอนแบบ Security Definer
CREATE OR REPLACE FUNCTION public.is_teacher()
RETURNS BOOLEAN AS $$
DECLARE
    is_tch BOOLEAN;
BEGIN
    SELECT EXISTS (SELECT 1 FROM public.teachers WHERE user_id = auth.uid()) INTO is_tch;
    RETURN is_tch;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

-- 3. เปิดใช้งาน Row Level Security (RLS)
ALTER TABLE public.teachers ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.students ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.progress ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.submissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.materials ENABLE ROW LEVEL SECURITY;

-- ยกเลิกสิทธิ์สาธารณะทั้งหมด
REVOKE ALL ON public.teachers FROM anon, authenticated;
REVOKE ALL ON public.students FROM anon, authenticated;
REVOKE ALL ON public.attempts FROM anon, authenticated;
REVOKE ALL ON public.progress FROM anon, authenticated;
REVOKE ALL ON public.submissions FROM anon, authenticated;
REVOKE ALL ON public.materials FROM anon, authenticated;

-- ให้สิทธิ์เฉพาะ Role Authenticated ในการดำเนินการ
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO authenticated;

-- 4. กำหนด Policies

-- Table: teachers
CREATE POLICY "Teachers can see all teachers" ON public.teachers FOR SELECT TO authenticated USING (true);

-- Table: students
CREATE POLICY "Students see own, teachers see all" ON public.students FOR SELECT TO authenticated
USING (user_id = auth.uid() OR public.is_teacher());

CREATE POLICY "Students can update own photo" ON public.students FOR UPDATE TO authenticated
USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid());

-- Table: attempts
CREATE POLICY "See own attempts or teacher sees all" ON public.attempts FOR SELECT TO authenticated
USING (user_id = auth.uid() OR public.is_teacher());
CREATE POLICY "Students insert own attempts" ON public.attempts FOR INSERT TO authenticated
WITH CHECK (user_id = auth.uid());

-- Table: progress
CREATE POLICY "See own progress or teacher sees all" ON public.progress FOR SELECT TO authenticated
USING (user_id = auth.uid() OR public.is_teacher());
CREATE POLICY "Insert own progress" ON public.progress FOR INSERT TO authenticated
WITH CHECK (user_id = auth.uid());
CREATE POLICY "Update own progress" ON public.progress FOR UPDATE TO authenticated
USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid());

-- Table: submissions
CREATE POLICY "See own submissions or teacher sees all" ON public.submissions FOR SELECT TO authenticated
USING (user_id = auth.uid() OR public.is_teacher());
CREATE POLICY "Insert own submissions" ON public.submissions FOR INSERT TO authenticated
WITH CHECK (user_id = auth.uid());
CREATE POLICY "Teacher updates submissions" ON public.submissions FOR UPDATE TO authenticated
USING (user_id = auth.uid() OR public.is_teacher());

-- Table: materials
CREATE POLICY "All authenticated can view materials" ON public.materials FOR SELECT TO authenticated USING (true);
CREATE POLICY "Only teacher can insert materials" ON public.materials FOR INSERT TO authenticated WITH CHECK (public.is_teacher());
CREATE POLICY "Only teacher can update materials" ON public.materials FOR UPDATE TO authenticated USING (public.is_teacher());
CREATE POLICY "Only teacher can delete materials" ON public.materials FOR DELETE TO authenticated USING (public.is_teacher());

-- 5. การป้องกันผู้เรียนแก้คะแนน submissions (Trigger)
-- นี่คือการปกป้องระดับคอลัมน์ แม้ Policy จะยอมให้ Update แต่ Trigger จะคืนค่าเดิมให้ถ้าไม่ใช่ผู้สอน
CREATE OR REPLACE FUNCTION public.protect_submission_scores()
RETURNS TRIGGER AS $$
BEGIN
    IF NOT public.is_teacher() THEN
        NEW.score = OLD.score;
        NEW.teacher_comment = OLD.teacher_comment;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE TRIGGER trg_prevent_student_score_update
BEFORE UPDATE ON public.submissions
FOR EACH ROW EXECUTE FUNCTION public.protect_submission_scores();

-- 6. Trigger ตรวจสอบและผูกผู้เรียนตอนสมัครสมาชิก
CREATE OR REPLACE FUNCTION public.check_and_link_student()
RETURNS TRIGGER AS $$
DECLARE
    is_student_format BOOLEAN;
    student_record RECORD;
    student_id_extracted VARCHAR(11);
BEGIN
    is_student_format := NEW.email ~ '^[0-9]{11}@';
    
    IF is_student_format THEN
        student_id_extracted := split_part(NEW.email, '@', 1);
        SELECT * INTO student_record FROM public.students WHERE id = student_id_extracted;
        
        IF NOT FOUND THEN
            RAISE EXCEPTION 'ไม่พบรหัสนักศึกษานี้ในระบบ (Access Denied)';
        END IF;
        
        IF student_record.user_id IS NOT NULL THEN
            RAISE EXCEPTION 'รหัสนักศึกษานี้ถูกลงทะเบียนไปแล้ว (Already Registered)';
        END IF;
        
        UPDATE public.students SET user_id = NEW.id WHERE id = student_id_extracted;
    END IF;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- สร้าง Trigger บน auth.users (ระบบของ Supabase จะยอมให้รันสคริปต์นี้ฐานะ superuser)
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
AFTER INSERT ON auth.users
FOR EACH ROW EXECUTE FUNCTION public.check_and_link_student();

-- 7. มุมมอง (View) สำหรับสรุปผล (ใช้ Security Invoker สำหรับผู้สอน)
CREATE OR REPLACE VIEW public.results WITH (security_invoker = true) AS
SELECT 
    s.id as student_id,
    s.title,
    s.first_name,
    s.last_name,
    s.section,
    s.user_id,
    s.photo_path,
    MAX(CASE WHEN a.kind = 'pre' THEN a.score ELSE NULL END) as pre_score,
    MAX(CASE WHEN a.kind = 'post' THEN a.score ELSE NULL END) as post_score,
    (SELECT COUNT(*) FROM public.progress p WHERE p.user_id = s.user_id AND p.done = true) as units_done,
    (SELECT score FROM public.submissions sub WHERE sub.user_id = s.user_id LIMIT 1) as task_score
FROM public.students s
LEFT JOIN public.attempts a ON s.user_id = a.user_id
GROUP BY s.id, s.title, s.first_name, s.last_name, s.section, s.user_id, s.photo_path;

-- 8. การจัดการ Storage Buckets และ RLS 
INSERT INTO storage.buckets (id, name, public) VALUES 
('photos', 'photos', false),
('submissions', 'submissions', false),
('materials', 'materials', false)
ON CONFLICT (id) DO NOTHING;

-- RLS ของ Storage
CREATE POLICY "Allow view own photo or teacher" ON storage.objects FOR SELECT TO authenticated
USING (bucket_id = 'photos' AND ((storage.foldername(name))[1] = auth.uid()::text OR public.is_teacher()));

CREATE POLICY "Allow upload own photo" ON storage.objects FOR INSERT TO authenticated
WITH CHECK (bucket_id = 'photos' AND (storage.foldername(name))[1] = auth.uid()::text AND (lower(right(name, 4)) IN ('.png', '.jpg')));

CREATE POLICY "Allow view own submission or teacher" ON storage.objects FOR SELECT TO authenticated
USING (bucket_id = 'submissions' AND ((storage.foldername(name))[1] = auth.uid()::text OR public.is_teacher()));

CREATE POLICY "Allow upload own submission" ON storage.objects FOR INSERT TO authenticated
WITH CHECK (bucket_id = 'submissions' AND (storage.foldername(name))[1] = auth.uid()::text AND (lower(right(name, 4)) IN ('.png', '.jpg', '.pdf', '.mp4')));

CREATE POLICY "All authenticated can view materials storage" ON storage.objects FOR SELECT TO authenticated
USING (bucket_id = 'materials');

CREATE POLICY "Only teacher can modify materials storage" ON storage.objects FOR ALL TO authenticated
USING (bucket_id = 'materials' AND public.is_teacher()) WITH CHECK (bucket_id = 'materials' AND public.is_teacher());

-- 9. ข้อมูลจำลองผู้เรียน 6 แถว
-- (ในใช้งานจริง ผู้สอนสามารถใช้ Table Editor ใน Supabase Import CSV เข้าตาราง students ได้)
INSERT INTO public.students (id, title, first_name, last_name, section) VALUES
('11111111111', 'เด็กชาย', 'สมชาย', 'ใจดี', '6/1'),
('22222222222', 'เด็กหญิง', 'สมหญิง', 'รักเรียน', '6/1'),
('33333333333', 'เด็กชาย', 'มานะ', 'อดทน', '6/1'),
('44444444444', 'เด็กหญิง', 'มานี', 'มีตา', '6/2'),
('55555555555', 'เด็กชาย', 'ปิติ', 'ขี่ม้า', '6/2'),
('66666666666', 'เด็กหญิง', 'ชูใจ', 'น่ารัก', '6/2')
ON CONFLICT (id) DO NOTHING;

-- 10. คำสั่งตั้งค่าผู้สอน (แก้ email เป็นของคุณ และลบ '--' ด้านหน้าเพื่อเปิดใช้งาน)
-- UPDATE auth.users SET raw_user_meta_data = '{"role": "teacher"}' WHERE email = 'teacher@school.com';
-- INSERT INTO public.teachers (user_id) SELECT id FROM auth.users WHERE email = 'teacher@school.com' ON CONFLICT DO NOTHING;