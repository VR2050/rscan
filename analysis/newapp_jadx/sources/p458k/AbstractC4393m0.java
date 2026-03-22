package p458k;

import java.io.Closeable;
import java.io.IOException;
import java.nio.charset.Charset;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.p472io.CloseableKt;
import kotlin.text.Charsets;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;
import p458k.p459p0.C4401c;
import p474l.InterfaceC4746h;

/* renamed from: k.m0 */
/* loaded from: classes3.dex */
public abstract class AbstractC4393m0 implements Closeable {

    /* renamed from: c */
    public static final a f11527c = new a(null);

    /* renamed from: k.m0$a */
    public static final class a {
        public a(DefaultConstructorMarker defaultConstructorMarker) {
        }
    }

    @NotNull
    /* renamed from: b */
    public final byte[] m5007b() {
        long mo4925d = mo4925d();
        if (mo4925d > Integer.MAX_VALUE) {
            throw new IOException(C1499a.m630p("Cannot buffer entire body for content length: ", mo4925d));
        }
        InterfaceC4746h mo4927k = mo4927k();
        try {
            byte[] mo5386l = mo4927k.mo5386l();
            CloseableKt.closeFinally(mo4927k, null);
            int length = mo5386l.length;
            if (mo4925d == -1 || mo4925d == length) {
                return mo5386l;
            }
            throw new IOException("Content-Length (" + mo4925d + ") and stream length (" + length + ") disagree");
        } finally {
        }
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        C4401c.m5019d(mo4927k());
    }

    /* renamed from: d */
    public abstract long mo4925d();

    @Nullable
    /* renamed from: e */
    public abstract C4371b0 mo4926e();

    @NotNull
    /* renamed from: k */
    public abstract InterfaceC4746h mo4927k();

    @NotNull
    /* renamed from: o */
    public final String m5008o() {
        Charset charset;
        InterfaceC4746h mo4927k = mo4927k();
        try {
            C4371b0 mo4926e = mo4926e();
            if (mo4926e == null || (charset = mo4926e.m4944a(Charsets.UTF_8)) == null) {
                charset = Charsets.UTF_8;
            }
            String mo5395w = mo4927k.mo5395w(C4401c.m5033r(mo4927k, charset));
            CloseableKt.closeFinally(mo4927k, null);
            return mo5395w;
        } finally {
        }
    }
}
