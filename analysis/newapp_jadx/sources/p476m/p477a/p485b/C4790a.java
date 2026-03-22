package p476m.p477a.p485b;

import java.io.IOException;

/* renamed from: m.a.b.a */
/* loaded from: classes3.dex */
public class C4790a extends IOException {
    private static final long serialVersionUID = 617550366255636674L;

    public C4790a() {
        super("Connection is closed");
    }

    public C4790a(String str) {
        super(C4873m.m5544a(str));
    }

    public C4790a(String str, Object... objArr) {
        super(C4873m.m5544a(String.format(str, objArr)));
    }
}
