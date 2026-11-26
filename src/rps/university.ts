import { randomInt } from 'node:crypto';
import { Router, type NextFunction, type Request, type Response } from 'express';
import type { RpConfig } from '../config.js';
import { claimsOfType, q, str, type Ctx } from './context.js';
import { LOCALES, translator } from '../i18n/index.js';
import { renderOffer } from './offer.js';
import { rpBase } from './common.js';

export const PROGRAMMES = ['cs', 'law', 'bio', 'art'] as const;
/** The demo exams of the examination page: id → days from today. */
export const EXAMS = [{ id: 'e1', days: 14, hour: '09:00', room: 'A.101' }, { id: 'e2', days: 21, hour: '14:00', room: 'B.204' }, { id: 'e3', days: 30, hour: '10:30', room: 'Aula Magna' }, { id: 'e4', days: 45, hour: '09:00', room: 'C.012' }] as const;

/** Is the Student ID still good for access: enrolled (status active) and within its validity? `undefined` fields are not judged. */
export function studentStanding(c: Record<string, unknown>, now = new Date()): { active: boolean; current: boolean; ok: boolean } {
  const status = typeof c.enrollment_status === 'string' ? c.enrollment_status : undefined;
  const until = typeof c.valid_until === 'string' && /^\d{4}-\d{2}-\d{2}/.test(c.valid_until) ? new Date(`${c.valid_until.slice(0, 10)}T23:59:59Z`) : undefined;
  const active = status === undefined || status === 'active';
  const current = until === undefined || until >= now;
  return { active, current, ok: active && current };
}

export function universityRouter(ctx: Ctx, rp: RpConfig): Router {
  const router = Router();
  router.use(rpBase(ctx, rp, 'university'));

  const pid = (req: Request) => claimsOfType(req.session, rp.id, 'pid');
  const sid = (req: Request) => claimsOfType(req.session, rp.id, 'studentid');
  router.use((req, res, next) => { res.locals.loggedIn = !!sid(req); next(); }); // the header offers the exams once a Student ID was presented
  const bc = (req: Request) => claimsOfType(req.session, rp.id, 'birth_certificate');
  const norm = (v: unknown) => str(v).trim().toLowerCase();

  /** Do the PID and the birth certificate describe the same person (name + date of birth)? */
  const sameName = (req: Request) => {
    const p = pid(req), b = bc(req);
    return !!p && !!b && norm(p.given_name) === norm(b.given_name) && norm(p.family_name) === norm(b.family_name) && str(p.birth_date) === str(b.birth_date);
  };

  /** The check blocks enrolment only when UNIVERSITY_REQUIRE_MATCH is on; otherwise a difference is just pointed out. */
  const identityMatches = (req: Request) => !ctx.cfg.universityRequireMatch || sameName(req);
  const differs = (req: Request) => !!pid(req) && !!bc(req) && !sameName(req);

  router.get('/', (req, res) => res.render('university/home', { title: 'Demo University', enrolled: !!req.session.enrolment, hasStudentId: !!sid(req) }));

  // multi-credential: one request for both; otherwise two requests in a row
  router.get('/start', (_req, res) => {
    const next = `/${rp.id}/documents`;
    res.redirect(ctx.cfg.multiCredential ? `/${rp.id}/verify?p=pid_bc&returnTo=${encodeURIComponent(next)}` : next);
  });

  router.get('/documents', (req, res) =>
    res.render('university/documents', { title: res.locals.t('uni.docs.title'), hasPid: !!pid(req), hasBc: !!bc(req), multi: ctx.cfg.multiCredential, mismatch: differs(req) && ctx.cfg.universityRequireMatch, differs: differs(req) && !ctx.cfg.universityRequireMatch }),
  );

  /** Forget the documents presented so far (e.g. PID and birth certificate of different people) and begin again. */
  router.post('/restart', (req, res) => {
    if (req.session.disclosed) delete req.session.disclosed[rp.id];
    res.redirect(`/${rp.id}/documents`);
  });

  const needBoth = (req: Request) => !!pid(req) && !!bc(req) && identityMatches(req);

  router.get('/enrol', (req, res) => {
    if (!needBoth(req)) return void res.redirect(`/${rp.id}/documents`);
    const p = pid(req)!, b = bc(req)!;
    res.render('university/enrol', { title: res.locals.t('uni.enrol.title'), p, b, programmes: PROGRAMMES, errors: {}, values: {} });
  });

  router.post('/enrol', (req, res) => {
    if (!needBoth(req)) return void res.redirect(`/${rp.id}/documents`);
    const programme = q(req.body?.programme) ?? '';
    const email = (q(req.body?.email) ?? '').trim();
    const errors: Record<string, string> = {};
    if (!(PROGRAMMES as readonly string[]).includes(programme)) errors.programme = 'form.err.required';
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) errors.email = 'form.err.email';
    if (q(req.body?.consent) !== 'yes') errors.consent = 'form.err.consent';
    if (Object.keys(errors).length) {
      return void res.status(422).render('university/enrol', { title: res.locals.t('uni.enrol.title'), p: pid(req)!, b: bc(req)!, programmes: PROGRAMMES, errors, values: { programme, email } });
    }
    req.session.enrolment = { studentNumber: `S${new Date().getFullYear()}${randomInt(10000, 99999)}`, programme, email, at: new Date().toISOString() };
    res.redirect(`/${rp.id}/confirmation`);
  });

  router.get('/confirmation', (req, res) => {
    const e = req.session.enrolment;
    const p = pid(req);
    if (!e || !p) return void res.redirect(`/${rp.id}/`);
    res.render('university/confirmation', { title: res.locals.t('uni.done.title'), e, p });
  });

  // ---- the Student ID attestation: issued after the enrolment, used to sign in
  router.post('/attestation/studentid', async (req, res) => {
    const e = req.session.enrolment;
    const p = pid(req);
    if (!e || !p) return void res.redirect(`/${rp.id}/`);
    const now = new Date();
    const y = now.getUTCMonth() >= 9 ? now.getUTCFullYear() : now.getUTCFullYear() - 1; // the academic year starts on 1 October
    const FACULTY: Record<string, string> = { cs: 'Faculty of Engineering', law: 'Faculty of Law', bio: 'Faculty of Sciences', art: 'Faculty of Arts' };
    const ISCED: Record<string, string> = { cs: '061', law: '042', bio: '051', art: '021' };
    const claims = {
      student_id: e.studentNumber, given_name: str(p.given_name), family_name: str(p.family_name),
      institution_name: 'Demo University', institution_id: 'E DEMOUNI01', enrollment_status: 'active',
      valid_from: `${y}-10-01`, valid_until: `${y + 1}-09-30`, issuance_date: now.toISOString().slice(0, 10),
      study_programme: res.locals.t(`prog.${e.programme}`), study_field_isced: ISCED[e.programme] ?? '', faculty: FACULTY[e.programme] ?? '',
      academic_year: `${y}/${y + 1}`, student_email: e.email,
    };
    await renderOffer(ctx, req, res, rp, 'studentid', claims, `/${rp.id}/confirmation`);
  });

  // ---- the diploma attestation (DC4EU-DE higher education diploma), for students signed in with the Student ID
  const DIPLOMA: Record<string, { level: string; eqf: number; id: string }> = { cs: { level: 'Master', eqf: 7, id: 'DEMO-MSC-CS' }, law: { level: 'Master', eqf: 7, id: 'DEMO-LLM-LAW' }, bio: { level: 'Master', eqf: 7, id: 'DEMO-MSC-BIO' }, art: { level: 'Bachelor', eqf: 6, id: 'DEMO-BA-ART' } };
  /** The programme of the signed-in student: the Student ID names it in the language it was issued in, so match it in every language. */
  const programmeOf = (req: Request): (typeof PROGRAMMES)[number] => {
    const given = str(sid(req)?.study_programme);
    const hit = given ? PROGRAMMES.find((k) => LOCALES.some((l) => translator(l.code)(`prog.${k}`) === given)) : undefined;
    return hit ?? (PROGRAMMES as readonly string[]).find((k) => k === req.session.enrolment?.programme) as (typeof PROGRAMMES)[number] ?? 'cs';
  };

  router.get('/diploma', (req, res, next) => (sid(req) ? next() : res.redirect(`/${rp.id}/login`)), (req, res) => {
    const c = sid(req)!;
    const k = programmeOf(req);
    res.render('university/diploma', { title: res.locals.t('uni.diploma.title'), c, ok: studentStanding(c).ok, programme: k, level: DIPLOMA[k]!, dob: str(pid(req)?.birth_date), error: undefined });
  });

  router.post('/attestation/diploma', (req, res, next) => (sid(req) ? next() : res.redirect(`/${rp.id}/login`)), async (req, res) => {
    const c = sid(req)!;
    const k = programmeOf(req);
    const dob = (q(req.body?.dob) ?? '').replace(/[\u0000-\u001f<>]/g, '').trim().slice(0, 40);
    if (!studentStanding(c).ok) return void res.status(403).render('error', { title: res.locals.t('error.title'), message: res.locals.t('uni.exams.not_eligible'), retryHref: `/${rp.id}/exams` });
    const d = DIPLOMA[k]!;
    const claims = {
      given_name: str(c.given_name), family_name: str(c.family_name), ...(dob ? { date_of_birth: dob } : {}), // no validation: whatever is entered is issued, nothing if left empty
     
      diploma_title: res.locals.t(`uni.diploma.t.${k}`), institution_name: 'Demo University', awarding_date: new Date().toISOString().slice(0, 10),
      degree_level: d.level, eqf_level: d.eqf, programme_id: d.id, issuing_authority: res.locals.t('uni.diploma.authority'), issuing_country: 'DE',
    };
    await renderOffer(ctx, req, res, rp, 'diploma', claims, `/${rp.id}/exams`);
  });

  // ---- returning students: sign in with the Student ID, then the examination page
  router.get('/login', (_req, res) => res.redirect(`/${rp.id}/verify?p=studentid&returnTo=${encodeURIComponent(`/${rp.id}/exams`)}`));
  const guard = (req: Request, res: Response, next: NextFunction) => (sid(req) ? next() : res.redirect(`/${rp.id}/login`));

  router.get('/exams', guard, (req, res) => {
    const c = sid(req)!;
    const standing = studentStanding(c);
    const regs = req.session.examRegs ?? [];
    const day = (n: number) => new Date(Date.now() + n * 86_400_000).toISOString().slice(0, 10);
    res.render('university/exams', { title: res.locals.t('uni.exams.title'), c, standing, exams: EXAMS.map((x) => ({ ...x, date: day(x.days), registered: regs.includes(x.id) })) });
  });

  router.post('/exams/register', guard, (req, res) => {
    const exam = EXAMS.find((x) => x.id === q(req.body?.exam));
    if (!exam || !studentStanding(sid(req)!).ok) return void res.status(exam ? 403 : 400).render('error', { title: res.locals.t('error.title'), message: res.locals.t('uni.exams.not_eligible'), retryHref: `/${rp.id}/exams` });
    req.session.examRegs = [...new Set([...(req.session.examRegs ?? []), exam.id])];
    req.session.flash = 'uni.exams.flash_registered';
    res.redirect(`/${rp.id}/exams`);
  });

  return router;
}
