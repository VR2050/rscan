package com.p397ta.utdid2.p400b.p401a;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Environment;
import com.p397ta.utdid2.p398a.p399a.C4136g;
import com.p397ta.utdid2.p400b.p401a.InterfaceC4139b;
import java.io.File;
import java.util.Map;

/* renamed from: com.ta.utdid2.b.a.c */
/* loaded from: classes2.dex */
public class C4140c {

    /* renamed from: a */
    private SharedPreferences f10819a;

    /* renamed from: a */
    private InterfaceC4139b f10821a;

    /* renamed from: a */
    private C4141d f10822a;

    /* renamed from: b */
    private String f10823b;

    /* renamed from: c */
    private String f10824c;

    /* renamed from: f */
    private boolean f10825f;

    /* renamed from: g */
    private boolean f10826g;

    /* renamed from: h */
    private boolean f10827h;

    /* renamed from: i */
    private boolean f10828i;
    private Context mContext;

    /* renamed from: a */
    private SharedPreferences.Editor f10818a = null;

    /* renamed from: a */
    private InterfaceC4139b.a f10820a = null;

    /* JADX WARN: Removed duplicated region for block: B:16:0x014b  */
    /* JADX WARN: Removed duplicated region for block: B:25:0x015b A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:35:0x0169  */
    /* JADX WARN: Removed duplicated region for block: B:39:0x0177 A[Catch: Exception -> 0x0181, TRY_LEAVE, TryCatch #4 {Exception -> 0x0181, blocks: (B:37:0x0173, B:39:0x0177), top: B:36:0x0173 }] */
    /* JADX WARN: Removed duplicated region for block: B:42:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public C4140c(android.content.Context r10, java.lang.String r11, java.lang.String r12, boolean r13, boolean r14) {
        /*
            Method dump skipped, instructions count: 386
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.p397ta.utdid2.p400b.p401a.C4140c.<init>(android.content.Context, java.lang.String, java.lang.String, boolean, boolean):void");
    }

    /* renamed from: a */
    private C4141d m4677a(String str) {
        File m4678a = m4678a(str);
        if (m4678a == null) {
            return null;
        }
        C4141d c4141d = new C4141d(m4678a.getAbsolutePath());
        this.f10822a = c4141d;
        return c4141d;
    }

    /* renamed from: b */
    private void m4681b() {
        InterfaceC4139b interfaceC4139b;
        SharedPreferences sharedPreferences;
        if (this.f10818a == null && (sharedPreferences = this.f10819a) != null) {
            this.f10818a = sharedPreferences.edit();
        }
        if (this.f10827h && this.f10820a == null && (interfaceC4139b = this.f10821a) != null) {
            this.f10820a = interfaceC4139b.mo4667a();
        }
        m4682c();
    }

    /* renamed from: c */
    private boolean m4682c() {
        InterfaceC4139b interfaceC4139b = this.f10821a;
        if (interfaceC4139b == null) {
            return false;
        }
        boolean mo4668b = interfaceC4139b.mo4668b();
        if (!mo4668b) {
            commit();
        }
        return mo4668b;
    }

    /* JADX WARN: Can't wrap try/catch for region: R(13:0|1|(4:3|(1:7)|8|(9:10|11|(1:15)|16|17|18|19|(4:21|(2:23|(2:25|(3:27|(1:29)(1:31)|30))(3:32|33|(1:35)))|40|(3:46|47|(1:49)))|52))|57|11|(2:13|15)|16|17|18|19|(0)|52|(1:(7:37|40|(2:42|44)|46|47|(0)|52))) */
    /* JADX WARN: Code restructure failed: missing block: B:36:0x007d, code lost:
    
        if (r4.commit() == false) goto L40;
     */
    /* JADX WARN: Code restructure failed: missing block: B:55:0x0037, code lost:
    
        r2 = move-exception;
     */
    /* JADX WARN: Code restructure failed: missing block: B:56:0x0038, code lost:
    
        r2.printStackTrace();
     */
    /* JADX WARN: Removed duplicated region for block: B:21:0x0041  */
    /* JADX WARN: Removed duplicated region for block: B:49:0x0096 A[Catch: Exception -> 0x009e, TRY_LEAVE, TryCatch #1 {Exception -> 0x009e, blocks: (B:47:0x0092, B:49:0x0096), top: B:46:0x0092 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean commit() {
        /*
            r6 = this;
            long r0 = java.lang.System.currentTimeMillis()
            android.content.SharedPreferences$Editor r2 = r6.f10818a
            r3 = 0
            if (r2 == 0) goto L20
            boolean r4 = r6.f10828i
            if (r4 != 0) goto L16
            android.content.SharedPreferences r4 = r6.f10819a
            if (r4 == 0) goto L16
            java.lang.String r4 = "t"
            r2.putLong(r4, r0)
        L16:
            android.content.SharedPreferences$Editor r0 = r6.f10818a
            boolean r0 = r0.commit()
            if (r0 != 0) goto L20
            r0 = 0
            goto L21
        L20:
            r0 = 1
        L21:
            android.content.SharedPreferences r1 = r6.f10819a
            if (r1 == 0) goto L31
            android.content.Context r1 = r6.mContext
            if (r1 == 0) goto L31
            java.lang.String r2 = r6.f10823b
            android.content.SharedPreferences r1 = r1.getSharedPreferences(r2, r3)
            r6.f10819a = r1
        L31:
            r1 = 0
            java.lang.String r1 = android.os.Environment.getExternalStorageState()     // Catch: java.lang.Exception -> L37
            goto L3b
        L37:
            r2 = move-exception
            r2.printStackTrace()
        L3b:
            boolean r2 = com.p397ta.utdid2.p398a.p399a.C4136g.m4661a(r1)
            if (r2 != 0) goto L9e
            java.lang.String r2 = "mounted"
            boolean r4 = r1.equals(r2)
            if (r4 == 0) goto L80
            com.ta.utdid2.b.a.b r4 = r6.f10821a
            if (r4 != 0) goto L75
            java.lang.String r4 = r6.f10824c
            com.ta.utdid2.b.a.d r4 = r6.m4677a(r4)
            if (r4 == 0) goto L80
            java.lang.String r5 = r6.f10823b
            com.ta.utdid2.b.a.b r4 = r4.m4689a(r5, r3)
            r6.f10821a = r4
            boolean r5 = r6.f10828i
            if (r5 != 0) goto L67
            android.content.SharedPreferences r5 = r6.f10819a
            r6.m4679a(r5, r4)
            goto L6c
        L67:
            android.content.SharedPreferences r5 = r6.f10819a
            r6.m4680a(r4, r5)
        L6c:
            com.ta.utdid2.b.a.b r4 = r6.f10821a
            com.ta.utdid2.b.a.b$a r4 = r4.mo4667a()
            r6.f10820a = r4
            goto L80
        L75:
            com.ta.utdid2.b.a.b$a r4 = r6.f10820a     // Catch: java.lang.Exception -> L7f
            if (r4 == 0) goto L80
            boolean r4 = r4.commit()     // Catch: java.lang.Exception -> L7f
            if (r4 != 0) goto L80
        L7f:
            r0 = 0
        L80:
            boolean r2 = r1.equals(r2)
            if (r2 != 0) goto L92
            java.lang.String r2 = "mounted_ro"
            boolean r1 = r1.equals(r2)
            if (r1 == 0) goto L9e
            com.ta.utdid2.b.a.b r1 = r6.f10821a
            if (r1 == 0) goto L9e
        L92:
            com.ta.utdid2.b.a.d r1 = r6.f10822a     // Catch: java.lang.Exception -> L9e
            if (r1 == 0) goto L9e
            java.lang.String r2 = r6.f10823b     // Catch: java.lang.Exception -> L9e
            com.ta.utdid2.b.a.b r1 = r1.m4689a(r2, r3)     // Catch: java.lang.Exception -> L9e
            r6.f10821a = r1     // Catch: java.lang.Exception -> L9e
        L9e:
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.p397ta.utdid2.p400b.p401a.C4140c.commit():boolean");
    }

    public String getString(String str) {
        m4682c();
        SharedPreferences sharedPreferences = this.f10819a;
        if (sharedPreferences != null) {
            String string = sharedPreferences.getString(str, "");
            if (!C4136g.m4661a(string)) {
                return string;
            }
        }
        InterfaceC4139b interfaceC4139b = this.f10821a;
        return interfaceC4139b != null ? interfaceC4139b.getString(str, "") : "";
    }

    public void putString(String str, String str2) {
        if (C4136g.m4661a(str) || str.equals("t")) {
            return;
        }
        m4681b();
        SharedPreferences.Editor editor = this.f10818a;
        if (editor != null) {
            editor.putString(str, str2);
        }
        InterfaceC4139b.a aVar = this.f10820a;
        if (aVar != null) {
            aVar.mo4673a(str, str2);
        }
    }

    public void remove(String str) {
        if (C4136g.m4661a(str) || str.equals("t")) {
            return;
        }
        m4681b();
        SharedPreferences.Editor editor = this.f10818a;
        if (editor != null) {
            editor.remove(str);
        }
        InterfaceC4139b.a aVar = this.f10820a;
        if (aVar != null) {
            aVar.mo4669a(str);
        }
    }

    /* renamed from: a */
    private File m4678a(String str) {
        File externalStorageDirectory = Environment.getExternalStorageDirectory();
        if (externalStorageDirectory == null) {
            return null;
        }
        File file = new File(String.format("%s%s%s", externalStorageDirectory.getAbsolutePath(), File.separator, str));
        if (!file.exists()) {
            file.mkdirs();
        }
        return file;
    }

    /* renamed from: a */
    private void m4679a(SharedPreferences sharedPreferences, InterfaceC4139b interfaceC4139b) {
        InterfaceC4139b.a mo4667a;
        if (sharedPreferences == null || interfaceC4139b == null || (mo4667a = interfaceC4139b.mo4667a()) == null) {
            return;
        }
        mo4667a.mo4675b();
        for (Map.Entry<String, ?> entry : sharedPreferences.getAll().entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();
            if (value instanceof String) {
                mo4667a.mo4673a(key, (String) value);
            } else if (value instanceof Integer) {
                mo4667a.mo4671a(key, ((Integer) value).intValue());
            } else if (value instanceof Long) {
                mo4667a.mo4672a(key, ((Long) value).longValue());
            } else if (value instanceof Float) {
                mo4667a.mo4670a(key, ((Float) value).floatValue());
            } else if (value instanceof Boolean) {
                mo4667a.mo4674a(key, ((Boolean) value).booleanValue());
            }
        }
        try {
            mo4667a.commit();
        } catch (Exception unused) {
        }
    }

    /* renamed from: a */
    private void m4680a(InterfaceC4139b interfaceC4139b, SharedPreferences sharedPreferences) {
        SharedPreferences.Editor edit;
        if (interfaceC4139b == null || sharedPreferences == null || (edit = sharedPreferences.edit()) == null) {
            return;
        }
        edit.clear();
        for (Map.Entry<String, ?> entry : interfaceC4139b.getAll().entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();
            if (value instanceof String) {
                edit.putString(key, (String) value);
            } else if (value instanceof Integer) {
                edit.putInt(key, ((Integer) value).intValue());
            } else if (value instanceof Long) {
                edit.putLong(key, ((Long) value).longValue());
            } else if (value instanceof Float) {
                edit.putFloat(key, ((Float) value).floatValue());
            } else if (value instanceof Boolean) {
                edit.putBoolean(key, ((Boolean) value).booleanValue());
            }
        }
        edit.commit();
    }
}
