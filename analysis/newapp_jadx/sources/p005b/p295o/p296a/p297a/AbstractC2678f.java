package p005b.p295o.p296a.p297a;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: b.o.a.a.f */
/* loaded from: classes2.dex */
public abstract class AbstractC2678f {

    /* renamed from: a */
    public C2675c f7281a = null;

    /* renamed from: b */
    public C2676d f7282b = null;

    /* renamed from: c */
    public AbstractC2678f f7283c = null;

    /* renamed from: d */
    public AbstractC2678f f7284d = null;

    /* renamed from: e */
    public int f7285e = 0;

    /* renamed from: b */
    public static void m3183b(Writer writer, String str) {
        int length = str.length();
        int i2 = 0;
        for (int i3 = 0; i3 < length; i3++) {
            char charAt = str.charAt(i3);
            String m628n = charAt >= 128 ? C1499a.m628n("&#", charAt, ";") : charAt != '\"' ? charAt != '<' ? charAt != '>' ? charAt != '&' ? charAt != '\'' ? null : "&#39;" : "&amp;" : "&gt;" : "&lt;" : "&quot;";
            if (m628n != null) {
                writer.write(str, i2, i3 - i2);
                writer.write(m628n);
                i2 = i3 + 1;
            }
        }
        if (i2 < length) {
            writer.write(str, i2, length - i2);
        }
    }

    /* renamed from: a */
    public abstract int mo3169a();

    /* renamed from: c */
    public void mo3170c() {
        this.f7285e = 0;
        C2675c c2675c = this.f7281a;
        if (c2675c != null) {
            c2675c.mo3170c();
        }
    }

    public abstract Object clone();

    /* renamed from: d */
    public abstract void mo3171d(Writer writer);

    /* renamed from: e */
    public abstract void mo3172e(Writer writer);

    public int hashCode() {
        if (this.f7285e == 0) {
            this.f7285e = mo3169a();
        }
        return this.f7285e;
    }

    public String toString() {
        try {
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            OutputStreamWriter outputStreamWriter = new OutputStreamWriter(byteArrayOutputStream);
            mo3171d(outputStreamWriter);
            outputStreamWriter.flush();
            return new String(byteArrayOutputStream.toByteArray());
        } catch (IOException unused) {
            return super.toString();
        }
    }
}
