package p005b.p113c0.p114a.p124i.p126o;

import androidx.annotation.NonNull;
import java.io.InputStream;
import p005b.p113c0.p114a.p124i.C1465k;
import p005b.p113c0.p114a.p124i.InterfaceC1460f;
import p005b.p113c0.p114a.p130l.C1495g;
import p476m.p477a.p478a.p479a.InterfaceC4775k;
import p476m.p477a.p485b.InterfaceC4800f;

/* renamed from: b.c0.a.i.o.a */
/* loaded from: classes2.dex */
public class C1471a implements InterfaceC4775k {

    /* renamed from: a */
    public final InterfaceC1460f f1459a;

    public C1471a(@NonNull InterfaceC1460f interfaceC1460f) {
        this.f1459a = interfaceC1460f;
    }

    @Override // p476m.p477a.p478a.p479a.InterfaceC4775k
    /* renamed from: b */
    public long mo548b() {
        return ((C1465k.b) this.f1459a).f1435a.mo541c();
    }

    @Override // p476m.p477a.p478a.p479a.InterfaceC4775k
    /* renamed from: c */
    public int mo549c() {
        long mo548b = mo548b();
        if (mo548b > 2147483647L) {
            return Integer.MAX_VALUE;
        }
        return (int) mo548b;
    }

    @Override // p476m.p477a.p478a.p479a.InterfaceC4775k
    /* renamed from: d */
    public InputStream mo550d() {
        return ((C1465k.b) this.f1459a).m537b();
    }

    @Override // p476m.p477a.p478a.p479a.InterfaceC4775k
    /* renamed from: e */
    public String mo551e() {
        InterfaceC4800f contentType = ((C1465k.b) this.f1459a).f1435a.getContentType();
        return contentType == null ? "" : contentType.getValue();
    }

    @Override // p476m.p477a.p478a.p479a.InterfaceC4775k
    public String getContentType() {
        C1495g m536a = ((C1465k.b) this.f1459a).m536a();
        if (m536a == null) {
            return null;
        }
        return m536a.toString();
    }

    public String toString() {
        return String.format("ContentLength=%s, Mime=%s", Long.valueOf(mo548b()), getContentType());
    }
}
