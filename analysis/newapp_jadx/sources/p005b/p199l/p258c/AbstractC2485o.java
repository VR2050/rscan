package p005b.p199l.p258c;

import java.io.IOException;
import java.io.StringWriter;
import p005b.p199l.p258c.p260c0.p261a0.C2435o;
import p005b.p199l.p258c.p265e0.C2474c;

/* renamed from: b.l.c.o */
/* loaded from: classes2.dex */
public abstract class AbstractC2485o {
    /* renamed from: a */
    public C2490t m2859a() {
        if (this instanceof C2490t) {
            return (C2490t) this;
        }
        throw new IllegalStateException("Not a JSON Primitive: " + this);
    }

    public String toString() {
        try {
            StringWriter stringWriter = new StringWriter();
            C2474c c2474c = new C2474c(stringWriter);
            c2474c.f6673k = true;
            C2435o.f6538X.mo2767c(c2474c, this);
            return stringWriter.toString();
        } catch (IOException e2) {
            throw new AssertionError(e2);
        }
    }
}
