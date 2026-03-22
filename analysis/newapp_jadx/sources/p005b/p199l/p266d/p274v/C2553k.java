package p005b.p199l.p266d.p274v;

import java.nio.charset.Charset;

/* renamed from: b.l.d.v.k */
/* loaded from: classes2.dex */
public final class C2553k {

    /* renamed from: a */
    public static final String f6956a;

    /* renamed from: b */
    public static final boolean f6957b;

    static {
        String name = Charset.defaultCharset().name();
        f6956a = name;
        f6957b = "SJIS".equalsIgnoreCase(name) || "EUC_JP".equalsIgnoreCase(name);
    }
}
