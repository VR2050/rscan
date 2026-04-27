package com.ta.utdid2.b.a;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Environment;
import com.ta.utdid2.a.a.g;
import com.ta.utdid2.b.a.b;
import java.io.File;
import java.util.Map;

/* JADX INFO: loaded from: classes3.dex */
public class c {

    /* JADX INFO: renamed from: a, reason: collision with other field name */
    private SharedPreferences f11a;

    /* JADX INFO: renamed from: a, reason: collision with other field name */
    private b f13a;

    /* JADX INFO: renamed from: a, reason: collision with other field name */
    private d f14a;
    private String b;
    private String c;
    private boolean f;
    private boolean g;
    private boolean h;
    private boolean i;
    private Context mContext;
    private SharedPreferences.Editor a = null;

    /* JADX INFO: renamed from: a, reason: collision with other field name */
    private b.a f12a = null;

    /* JADX WARN: Removed duplicated region for block: B:68:0x0152  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public c(android.content.Context r10, java.lang.String r11, java.lang.String r12, boolean r13, boolean r14) throws java.lang.Throwable {
        /*
            Method dump skipped, instruction units count: 402
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.ta.utdid2.b.a.c.<init>(android.content.Context, java.lang.String, java.lang.String, boolean, boolean):void");
    }

    private d a(String str) {
        File fileM18a = m18a(str);
        if (fileM18a != null) {
            d dVar = new d(fileM18a.getAbsolutePath());
            this.f14a = dVar;
            return dVar;
        }
        return null;
    }

    /* JADX INFO: renamed from: a, reason: collision with other method in class */
    private File m18a(String str) {
        File externalStorageDirectory = Environment.getExternalStorageDirectory();
        if (externalStorageDirectory != null) {
            File file = new File(String.format("%s%s%s", externalStorageDirectory.getAbsolutePath(), File.separator, str));
            if (!file.exists()) {
                file.mkdirs();
            }
            return file;
        }
        return null;
    }

    private void a(SharedPreferences sharedPreferences, b bVar) {
        b.a aVarA;
        if (sharedPreferences != null && bVar != null && (aVarA = bVar.a()) != null) {
            aVarA.b();
            for (Map.Entry<String, ?> entry : sharedPreferences.getAll().entrySet()) {
                String key = entry.getKey();
                Object value = entry.getValue();
                if (value instanceof String) {
                    aVarA.a(key, (String) value);
                } else if (value instanceof Integer) {
                    aVarA.a(key, ((Integer) value).intValue());
                } else if (value instanceof Long) {
                    aVarA.a(key, ((Long) value).longValue());
                } else if (value instanceof Float) {
                    aVarA.a(key, ((Float) value).floatValue());
                } else if (value instanceof Boolean) {
                    aVarA.a(key, ((Boolean) value).booleanValue());
                }
            }
            try {
                aVarA.commit();
            } catch (Exception e) {
            }
        }
    }

    private void a(b bVar, SharedPreferences sharedPreferences) {
        SharedPreferences.Editor editorEdit;
        if (bVar != null && sharedPreferences != null && (editorEdit = sharedPreferences.edit()) != null) {
            editorEdit.clear();
            for (Map.Entry<String, ?> entry : bVar.getAll().entrySet()) {
                String key = entry.getKey();
                Object value = entry.getValue();
                if (value instanceof String) {
                    editorEdit.putString(key, (String) value);
                } else if (value instanceof Integer) {
                    editorEdit.putInt(key, ((Integer) value).intValue());
                } else if (value instanceof Long) {
                    editorEdit.putLong(key, ((Long) value).longValue());
                } else if (value instanceof Float) {
                    editorEdit.putFloat(key, ((Float) value).floatValue());
                } else if (value instanceof Boolean) {
                    editorEdit.putBoolean(key, ((Boolean) value).booleanValue());
                }
            }
            editorEdit.commit();
        }
    }

    private boolean c() throws Throwable {
        b bVar = this.f13a;
        if (bVar != null) {
            boolean zB = bVar.b();
            if (!zB) {
                commit();
            }
            return zB;
        }
        return false;
    }

    private void b() throws Throwable {
        b bVar;
        SharedPreferences sharedPreferences;
        if (this.a == null && (sharedPreferences = this.f11a) != null) {
            this.a = sharedPreferences.edit();
        }
        if (this.h && this.f12a == null && (bVar = this.f13a) != null) {
            this.f12a = bVar.a();
        }
        c();
    }

    public void putString(String key, String value) throws Throwable {
        if (!g.m17a(key) && !key.equals("t")) {
            b();
            SharedPreferences.Editor editor = this.a;
            if (editor != null) {
                editor.putString(key, value);
            }
            b.a aVar = this.f12a;
            if (aVar != null) {
                aVar.a(key, value);
            }
        }
    }

    public void remove(String key) throws Throwable {
        if (!g.m17a(key) && !key.equals("t")) {
            b();
            SharedPreferences.Editor editor = this.a;
            if (editor != null) {
                editor.remove(key);
            }
            b.a aVar = this.f12a;
            if (aVar != null) {
                aVar.a(key);
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:12:0x0021  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean commit() throws java.lang.Throwable {
        /*
            r6 = this;
            long r0 = java.lang.System.currentTimeMillis()
            android.content.SharedPreferences$Editor r2 = r6.a
            r3 = 0
            if (r2 == 0) goto L21
            boolean r4 = r6.i
            if (r4 != 0) goto L17
            android.content.SharedPreferences r4 = r6.f11a
            if (r4 == 0) goto L17
            java.lang.String r4 = "t"
            r2.putLong(r4, r0)
        L17:
            android.content.SharedPreferences$Editor r0 = r6.a
            boolean r0 = r0.commit()
            if (r0 != 0) goto L21
            r0 = 0
            goto L22
        L21:
            r0 = 1
        L22:
            android.content.SharedPreferences r1 = r6.f11a
            if (r1 == 0) goto L32
            android.content.Context r1 = r6.mContext
            if (r1 == 0) goto L32
            java.lang.String r2 = r6.b
            android.content.SharedPreferences r1 = r1.getSharedPreferences(r2, r3)
            r6.f11a = r1
        L32:
            r1 = 0
            java.lang.String r1 = android.os.Environment.getExternalStorageState()     // Catch: java.lang.Exception -> L38
            goto L3c
        L38:
            r2 = move-exception
            r2.printStackTrace()
        L3c:
            boolean r2 = com.ta.utdid2.a.a.g.m17a(r1)
            if (r2 != 0) goto La8
            java.lang.String r2 = "mounted"
            boolean r4 = r1.equals(r2)
            if (r4 == 0) goto L86
            com.ta.utdid2.b.a.b r4 = r6.f13a
            if (r4 != 0) goto L76
            java.lang.String r4 = r6.c
            com.ta.utdid2.b.a.d r4 = r6.a(r4)
            if (r4 == 0) goto L75
            java.lang.String r5 = r6.b
            com.ta.utdid2.b.a.b r4 = r4.a(r5, r3)
            r6.f13a = r4
            boolean r5 = r6.i
            if (r5 != 0) goto L68
            android.content.SharedPreferences r5 = r6.f11a
            r6.a(r5, r4)
            goto L6d
        L68:
            android.content.SharedPreferences r5 = r6.f11a
            r6.a(r4, r5)
        L6d:
            com.ta.utdid2.b.a.b r4 = r6.f13a
            com.ta.utdid2.b.a.b$a r4 = r4.a()
            r6.f12a = r4
        L75:
            goto L86
        L76:
            com.ta.utdid2.b.a.b$a r4 = r6.f12a     // Catch: java.lang.Exception -> L84
            if (r4 == 0) goto L83
            com.ta.utdid2.b.a.b$a r4 = r6.f12a     // Catch: java.lang.Exception -> L84
            boolean r4 = r4.commit()     // Catch: java.lang.Exception -> L84
            if (r4 != 0) goto L83
            r0 = 0
        L83:
            goto L86
        L84:
            r0 = move-exception
            r0 = 0
        L86:
            boolean r2 = r1.equals(r2)
            if (r2 != 0) goto L98
            java.lang.String r2 = "mounted_ro"
            boolean r1 = r1.equals(r2)
            if (r1 == 0) goto La8
            com.ta.utdid2.b.a.b r1 = r6.f13a
            if (r1 == 0) goto La8
        L98:
            com.ta.utdid2.b.a.d r1 = r6.f14a     // Catch: java.lang.Exception -> La7
            if (r1 == 0) goto La6
            com.ta.utdid2.b.a.d r1 = r6.f14a     // Catch: java.lang.Exception -> La7
            java.lang.String r2 = r6.b     // Catch: java.lang.Exception -> La7
            com.ta.utdid2.b.a.b r1 = r1.a(r2, r3)     // Catch: java.lang.Exception -> La7
            r6.f13a = r1     // Catch: java.lang.Exception -> La7
        La6:
            goto La8
        La7:
            r1 = move-exception
        La8:
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.ta.utdid2.b.a.c.commit():boolean");
    }

    public String getString(String key) throws Throwable {
        c();
        SharedPreferences sharedPreferences = this.f11a;
        if (sharedPreferences != null) {
            String string = sharedPreferences.getString(key, "");
            if (!g.m17a(string)) {
                return string;
            }
        }
        b bVar = this.f13a;
        return bVar != null ? bVar.getString(key, "") : "";
    }
}
