package p005b.p295o.p296a.p297a;

import java.io.Writer;

/* renamed from: b.o.a.a.n */
/* loaded from: classes2.dex */
public class C2686n extends AbstractC2678f {

    /* renamed from: f */
    public StringBuffer f7341f;

    public C2686n(String str) {
        this.f7341f = new StringBuffer(str);
    }

    @Override // p005b.p295o.p296a.p297a.AbstractC2678f
    /* renamed from: a */
    public int mo3169a() {
        return this.f7341f.toString().hashCode();
    }

    @Override // p005b.p295o.p296a.p297a.AbstractC2678f
    public Object clone() {
        return new C2686n(this.f7341f.toString());
    }

    @Override // p005b.p295o.p296a.p297a.AbstractC2678f
    /* renamed from: d */
    public void mo3171d(Writer writer) {
        writer.write(this.f7341f.toString());
    }

    @Override // p005b.p295o.p296a.p297a.AbstractC2678f
    /* renamed from: e */
    public void mo3172e(Writer writer) {
        String stringBuffer = this.f7341f.toString();
        if (stringBuffer.length() < 50) {
            AbstractC2678f.m3183b(writer, stringBuffer);
            return;
        }
        writer.write("<![CDATA[");
        writer.write(stringBuffer);
        writer.write("]]>");
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof C2686n) {
            return this.f7341f.toString().equals(((C2686n) obj).f7341f.toString());
        }
        return false;
    }

    /* renamed from: f */
    public String m3224f() {
        return this.f7341f.toString();
    }
}
