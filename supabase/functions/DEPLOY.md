# نشر وظيفة دعوة المسؤولين

من جذر المستودع شغّل:
`supabase functions deploy invite-platform-admin`

ثم أضف أسرار الوظيفة في إعدادات Supabase Edge Functions:
- `SUPABASE_URL`
- `SUPABASE_ANON_KEY`
- `SUPABASE_SERVICE_ROLE_KEY`

لا تضع مفتاح service role في ملفات الواجهة أو GitHub. هذه الوظيفة تتحقق من جلسة المستخدم ومن كونه مديراً عاماً قبل إرسال الدعوة. لا تنشر الوظيفة قبل تطبيق SQL migration في مشروع University Platform الجديد.
