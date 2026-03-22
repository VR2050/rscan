package p476m.p477a.p478a.p479a.p480l;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import p005b.p131d.p132a.p133a.C1499a;
import p476m.p477a.p478a.p479a.C4771g;
import p476m.p477a.p478a.p479a.C4773i;
import p476m.p477a.p478a.p479a.InterfaceC4765a;
import p476m.p477a.p478a.p483b.C4786c;
import p476m.p477a.p478a.p483b.p484d.C4787a;
import p476m.p477a.p478a.p483b.p484d.C4788b;

/* renamed from: m.a.a.a.l.a */
/* loaded from: classes3.dex */
public class C4776a implements InterfaceC4765a {

    /* renamed from: a */
    public static final String f12234a = UUID.randomUUID().toString().replace('-', '_');

    /* renamed from: b */
    public static final AtomicInteger f12235b = new AtomicInteger(0);

    /* renamed from: c */
    public String f12236c;

    /* renamed from: d */
    public final String f12237d;

    /* renamed from: e */
    public boolean f12238e;

    /* renamed from: f */
    public final String f12239f;

    /* renamed from: h */
    public final int f12241h;

    /* renamed from: i */
    public final File f12242i;

    /* renamed from: j */
    public byte[] f12243j;

    /* renamed from: k */
    public transient C4788b f12244k;

    /* renamed from: l */
    public transient File f12245l;

    /* renamed from: g */
    public long f12240g = -1;

    /* renamed from: m */
    public String f12246m = "ISO-8859-1";

    public C4776a(String str, String str2, boolean z, String str3, int i2, File file) {
        this.f12236c = str;
        this.f12237d = str2;
        this.f12238e = z;
        this.f12239f = str3;
        this.f12241h = i2;
        this.f12242i = file;
    }

    @Override // p476m.p477a.p478a.p479a.InterfaceC4765a
    /* renamed from: a */
    public void mo5428a() {
        this.f12243j = null;
        File m5455g = m5455g();
        if (m5455g == null || m5457i() || !m5455g.exists()) {
            return;
        }
        m5455g.delete();
    }

    @Override // p476m.p477a.p478a.p479a.InterfaceC4765a
    /* renamed from: b */
    public String mo5429b() {
        byte[] m5453e = m5453e();
        C4773i c4773i = new C4773i();
        c4773i.f12233f = true;
        String str = c4773i.m5452d(this.f12237d, ';').get("charset");
        if (str == null) {
            str = this.f12246m;
        }
        try {
            return new String(m5453e, str);
        } catch (UnsupportedEncodingException unused) {
            return new String(m5453e);
        }
    }

    @Override // p476m.p477a.p478a.p479a.InterfaceC4765a
    /* renamed from: c */
    public String mo5430c() {
        return this.f12236c;
    }

    @Override // p476m.p477a.p478a.p479a.InterfaceC4765a
    /* renamed from: d */
    public boolean mo5431d() {
        return this.f12238e;
    }

    /* renamed from: e */
    public byte[] m5453e() {
        FileInputStream fileInputStream;
        C4788b c4788b;
        FileInputStream fileInputStream2 = null;
        if (m5457i()) {
            if (this.f12243j == null && (c4788b = this.f12244k) != null) {
                C4787a c4787a = c4788b.f12272g;
                this.f12243j = c4787a != null ? c4787a.m5466d() : null;
            }
            return this.f12243j;
        }
        byte[] bArr = new byte[(int) getSize()];
        try {
            fileInputStream = new FileInputStream(this.f12244k.f12274i);
            try {
                C4786c.m5464a(fileInputStream, bArr);
                try {
                    fileInputStream.close();
                } catch (IOException unused) {
                }
                return bArr;
            } catch (IOException unused2) {
                int i2 = C4786c.f12262a;
                if (fileInputStream == null) {
                    return null;
                }
                try {
                    fileInputStream.close();
                    return null;
                } catch (IOException unused3) {
                    return null;
                }
            } catch (Throwable th) {
                th = th;
                fileInputStream2 = fileInputStream;
                int i3 = C4786c.f12262a;
                if (fileInputStream2 != null) {
                    try {
                        fileInputStream2.close();
                    } catch (IOException unused4) {
                    }
                }
                throw th;
            }
        } catch (IOException unused5) {
            fileInputStream = null;
        } catch (Throwable th2) {
            th = th2;
        }
    }

    /* renamed from: f */
    public OutputStream m5454f() {
        if (this.f12244k == null) {
            this.f12244k = new C4788b(this.f12241h, m5456h());
        }
        return this.f12244k;
    }

    public void finalize() {
        File file;
        C4788b c4788b = this.f12244k;
        if (c4788b == null || c4788b.m5468d() || (file = this.f12244k.f12274i) == null || !file.exists()) {
            return;
        }
        file.delete();
    }

    /* renamed from: g */
    public File m5455g() {
        if (this.f12244k == null || m5457i()) {
            return null;
        }
        return this.f12244k.f12274i;
    }

    @Override // p476m.p477a.p478a.p479a.InterfaceC4765a
    public String getContentType() {
        return this.f12237d;
    }

    @Override // p476m.p477a.p478a.p479a.InterfaceC4765a
    public long getSize() {
        int length;
        long j2 = this.f12240g;
        if (j2 >= 0) {
            return j2;
        }
        byte[] bArr = this.f12243j;
        if (bArr != null) {
            length = bArr.length;
        } else {
            if (!this.f12244k.m5468d()) {
                return this.f12244k.f12274i.length();
            }
            C4787a c4787a = this.f12244k.f12272g;
            length = (c4787a != null ? c4787a.m5466d() : null).length;
        }
        return length;
    }

    @Override // p476m.p477a.p478a.p479a.InterfaceC4765a
    public String getString(String str) {
        return new String(m5453e(), str);
    }

    /* renamed from: h */
    public File m5456h() {
        if (this.f12245l == null) {
            File file = this.f12242i;
            if (file == null) {
                file = new File(System.getProperty("java.io.tmpdir"));
            }
            Object[] objArr = new Object[2];
            objArr[0] = f12234a;
            int andIncrement = f12235b.getAndIncrement();
            String num = Integer.toString(andIncrement);
            if (andIncrement < 100000000) {
                num = C1499a.m637w("00000000", num).substring(num.length());
            }
            objArr[1] = num;
            this.f12245l = new File(file, String.format("upload_%s_%s.tmp", objArr));
        }
        return this.f12245l;
    }

    /* renamed from: i */
    public boolean m5457i() {
        if (this.f12243j != null) {
            return true;
        }
        return this.f12244k.m5468d();
    }

    public String toString() {
        Object[] objArr = new Object[5];
        String str = this.f12239f;
        if (str == null || str.indexOf(0) == -1) {
            objArr[0] = str;
            objArr[1] = m5455g();
            objArr[2] = Long.valueOf(getSize());
            objArr[3] = Boolean.valueOf(this.f12238e);
            objArr[4] = this.f12236c;
            return String.format("name=%s, StoreLocation=%s, size=%s bytes, isFormField=%s, FieldName=%s", objArr);
        }
        StringBuilder sb = new StringBuilder();
        for (int i2 = 0; i2 < str.length(); i2++) {
            char charAt = str.charAt(i2);
            if (charAt != 0) {
                sb.append(charAt);
            } else {
                sb.append("\\0");
            }
        }
        throw new C4771g(str, "Invalid file name: " + ((Object) sb));
    }
}
