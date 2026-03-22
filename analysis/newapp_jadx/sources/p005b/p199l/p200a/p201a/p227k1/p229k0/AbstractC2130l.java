package p005b.p199l.p200a.p201a.p227k1.p229k0;

import androidx.annotation.Nullable;
import com.google.android.exoplayer2.Format;
import java.util.Objects;
import p005b.p199l.p200a.p201a.p248o1.C2324p;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m;

/* renamed from: b.l.a.a.k1.k0.l */
/* loaded from: classes.dex */
public abstract class AbstractC2130l extends AbstractC2122d {

    /* renamed from: i */
    public final long f4690i;

    public AbstractC2130l(InterfaceC2321m interfaceC2321m, C2324p c2324p, Format format, int i2, @Nullable Object obj, long j2, long j3, long j4) {
        super(interfaceC2321m, c2324p, 1, format, i2, obj, j2, j3);
        Objects.requireNonNull(format);
        this.f4690i = j4;
    }

    /* renamed from: c */
    public long mo1860c() {
        long j2 = this.f4690i;
        if (j2 != -1) {
            return 1 + j2;
        }
        return -1L;
    }

    /* renamed from: d */
    public abstract boolean mo1861d();
}
