package p005b.p199l.p200a.p201a.p245m1;

import androidx.annotation.Nullable;
import com.google.android.exoplayer2.Format;
import com.google.android.exoplayer2.source.TrackGroup;
import java.util.List;
import p005b.p199l.p200a.p201a.p227k1.p229k0.AbstractC2130l;
import p005b.p199l.p200a.p201a.p227k1.p229k0.InterfaceC2131m;

/* renamed from: b.l.a.a.m1.f */
/* loaded from: classes.dex */
public interface InterfaceC2257f {

    /* renamed from: b.l.a.a.m1.f$b */
    public interface b {
    }

    /* renamed from: a */
    TrackGroup mo2149a();

    /* renamed from: b */
    int mo1941b();

    /* renamed from: c */
    boolean mo2150c(int i2, long j2);

    /* renamed from: d */
    void mo2151d();

    /* renamed from: e */
    Format mo2152e(int i2);

    /* renamed from: f */
    void mo2145f();

    /* renamed from: g */
    int mo2153g(int i2);

    /* renamed from: h */
    int mo2146h(long j2, List<? extends AbstractC2130l> list);

    /* renamed from: i */
    int mo2154i(Format format);

    /* renamed from: j */
    void mo1942j(long j2, long j3, long j4, List<? extends AbstractC2130l> list, InterfaceC2131m[] interfaceC2131mArr);

    /* renamed from: k */
    int mo2155k();

    /* renamed from: l */
    Format mo2156l();

    int length();

    /* renamed from: m */
    int mo1943m();

    /* renamed from: n */
    void mo2147n(float f2);

    @Nullable
    /* renamed from: o */
    Object mo1944o();

    /* renamed from: p */
    void mo2157p();

    /* renamed from: q */
    int mo2158q(int i2);

    /* renamed from: b.l.a.a.m1.f$a */
    public static final class a {

        /* renamed from: a */
        public final TrackGroup f5655a;

        /* renamed from: b */
        public final int[] f5656b;

        /* renamed from: c */
        public final int f5657c;

        /* renamed from: d */
        @Nullable
        public final Object f5658d;

        public a(TrackGroup trackGroup, int... iArr) {
            this.f5655a = trackGroup;
            this.f5656b = iArr;
            this.f5657c = 0;
            this.f5658d = null;
        }

        public a(TrackGroup trackGroup, int[] iArr, int i2, @Nullable Object obj) {
            this.f5655a = trackGroup;
            this.f5656b = iArr;
            this.f5657c = i2;
            this.f5658d = obj;
        }
    }
}
