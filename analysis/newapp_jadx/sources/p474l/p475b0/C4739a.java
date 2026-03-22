package p474l.p475b0;

import java.util.Objects;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Charsets;
import org.jetbrains.annotations.NotNull;
import p474l.C4744f;

/* renamed from: l.b0.a */
/* loaded from: classes3.dex */
public final class C4739a {

    /* renamed from: a */
    @NotNull
    public static final byte[] f12126a;

    static {
        Intrinsics.checkNotNullParameter("0123456789abcdef", "$this$asUtf8ToByteArray");
        byte[] bytes = "0123456789abcdef".getBytes(Charsets.UTF_8);
        Intrinsics.checkNotNullExpressionValue(bytes, "(this as java.lang.String).getBytes(charset)");
        f12126a = bytes;
    }

    @NotNull
    /* renamed from: a */
    public static final String m5347a(@NotNull C4744f readUtf8Line, long j2) {
        Intrinsics.checkNotNullParameter(readUtf8Line, "$this$readUtf8Line");
        if (j2 > 0) {
            long j3 = j2 - 1;
            if (readUtf8Line.m5394v(j3) == ((byte) 13)) {
                String m5362P = readUtf8Line.m5362P(j3, Charsets.UTF_8);
                readUtf8Line.skip(2L);
                return m5362P;
            }
        }
        Objects.requireNonNull(readUtf8Line);
        String m5362P2 = readUtf8Line.m5362P(j2, Charsets.UTF_8);
        readUtf8Line.skip(1L);
        return m5362P2;
    }

    /* JADX WARN: Code restructure failed: missing block: B:30:0x005b, code lost:
    
        if (r19 == false) goto L25;
     */
    /* JADX WARN: Code restructure failed: missing block: B:31:0x005d, code lost:
    
        return -2;
     */
    /* JADX WARN: Code restructure failed: missing block: B:32:0x005e, code lost:
    
        return r10;
     */
    /* renamed from: b */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final int m5348b(@org.jetbrains.annotations.NotNull p474l.C4744f r17, @org.jetbrains.annotations.NotNull p474l.C4755q r18, boolean r19) {
        /*
            Method dump skipped, instructions count: 175
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p474l.p475b0.C4739a.m5348b(l.f, l.q, boolean):int");
    }
}
