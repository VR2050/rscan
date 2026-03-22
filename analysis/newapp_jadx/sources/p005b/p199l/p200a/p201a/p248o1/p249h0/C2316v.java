package p005b.p199l.p200a.p201a.p248o1.p249h0;

import androidx.annotation.Nullable;
import java.io.File;
import java.util.regex.Pattern;

/* renamed from: b.l.a.a.o1.h0.v */
/* loaded from: classes.dex */
public final class C2316v extends C2305k {

    /* renamed from: j */
    public static final Pattern f5913j = Pattern.compile("^(.+)\\.(\\d+)\\.(\\d+)\\.v1\\.exo$", 32);

    /* renamed from: k */
    public static final Pattern f5914k = Pattern.compile("^(.+)\\.(\\d+)\\.(\\d+)\\.v2\\.exo$", 32);

    /* renamed from: l */
    public static final Pattern f5915l = Pattern.compile("^(\\d+)\\.(\\d+)\\.(\\d+)\\.v3\\.exo$", 32);

    public C2316v(String str, long j2, long j3, long j4, @Nullable File file) {
        super(str, j2, j3, j4, file);
    }

    /* JADX WARN: Code restructure failed: missing block: B:28:0x0085, code lost:
    
        if (r1 == null) goto L29;
     */
    /* JADX WARN: Code restructure failed: missing block: B:30:0x00c1, code lost:
    
        if (r16.renameTo(r1) == false) goto L29;
     */
    @androidx.annotation.Nullable
    /* renamed from: b */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static p005b.p199l.p200a.p201a.p248o1.p249h0.C2316v m2263b(java.io.File r16, long r17, long r19, p005b.p199l.p200a.p201a.p248o1.p249h0.C2308n r21) {
        /*
            Method dump skipped, instructions count: 299
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p248o1.p249h0.C2316v.m2263b(java.io.File, long, long, b.l.a.a.o1.h0.n):b.l.a.a.o1.h0.v");
    }

    /* renamed from: c */
    public static File m2264c(File file, int i2, long j2, long j3) {
        return new File(file, i2 + "." + j2 + "." + j3 + ".v3.exo");
    }
}
