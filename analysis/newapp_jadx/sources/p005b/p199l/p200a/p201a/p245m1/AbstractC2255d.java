package p005b.p199l.p200a.p201a.p245m1;

import androidx.annotation.Nullable;
import com.google.android.exoplayer2.source.TrackGroupArray;
import java.util.Arrays;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* renamed from: b.l.a.a.m1.d */
/* loaded from: classes.dex */
public abstract class AbstractC2255d extends AbstractC2259h {

    /* renamed from: b */
    @Nullable
    public a f5647b;

    /* renamed from: b.l.a.a.m1.d$a */
    public static final class a {

        /* renamed from: a */
        @Deprecated
        public final int f5648a;

        /* renamed from: b */
        public final int f5649b;

        /* renamed from: c */
        public final int[] f5650c;

        /* renamed from: d */
        public final TrackGroupArray[] f5651d;

        /* renamed from: e */
        public final int[] f5652e;

        /* renamed from: f */
        public final int[][][] f5653f;

        /* renamed from: g */
        public final TrackGroupArray f5654g;

        public a(int[] iArr, TrackGroupArray[] trackGroupArrayArr, int[] iArr2, int[][][] iArr3, TrackGroupArray trackGroupArray) {
            this.f5650c = iArr;
            this.f5651d = trackGroupArrayArr;
            this.f5653f = iArr3;
            this.f5652e = iArr2;
            this.f5654g = trackGroupArray;
            int length = iArr.length;
            this.f5649b = length;
            this.f5648a = length;
        }

        /* renamed from: a */
        public int m2162a(int i2, int i3, boolean z) {
            int i4 = this.f5651d[i2].f9398f[i3].f9393c;
            int[] iArr = new int[i4];
            int i5 = 0;
            int i6 = 0;
            for (int i7 = 0; i7 < i4; i7++) {
                int i8 = this.f5653f[i2][i3][i7] & 7;
                if (i8 == 4 || (z && i8 == 3)) {
                    iArr[i6] = i7;
                    i6++;
                }
            }
            int[] copyOf = Arrays.copyOf(iArr, i6);
            String str = null;
            int i9 = 16;
            boolean z2 = false;
            int i10 = 0;
            while (i5 < copyOf.length) {
                String str2 = this.f5651d[i2].f9398f[i3].f9394e[copyOf[i5]].f9245l;
                int i11 = i10 + 1;
                if (i10 == 0) {
                    str = str2;
                } else {
                    z2 |= !C2344d0.m2323a(str, str2);
                }
                i9 = Math.min(i9, this.f5653f[i2][i3][i5] & 24);
                i5++;
                i10 = i11;
            }
            return z2 ? Math.min(i9, this.f5652e[i2]) : i9;
        }
    }

    @Override // p005b.p199l.p200a.p201a.p245m1.AbstractC2259h
    /* renamed from: a */
    public final void mo2160a(Object obj) {
        this.f5647b = (a) obj;
    }

    /* JADX WARN: Code restructure failed: missing block: B:131:0x0338, code lost:
    
        if (r1 < 0) goto L168;
     */
    /* JADX WARN: Code restructure failed: missing block: B:139:0x0355, code lost:
    
        r1 = true;
     */
    /* JADX WARN: Code restructure failed: missing block: B:566:0x098f, code lost:
    
        if (r7 != 2) goto L472;
     */
    /* JADX WARN: Removed duplicated region for block: B:121:0x0313  */
    /* JADX WARN: Removed duplicated region for block: B:124:0x0321  */
    /* JADX WARN: Removed duplicated region for block: B:126:0x0325  */
    /* JADX WARN: Removed duplicated region for block: B:128:0x032a  */
    /* JADX WARN: Removed duplicated region for block: B:134:0x035d  */
    /* JADX WARN: Removed duplicated region for block: B:148:0x0359  */
    /* JADX WARN: Removed duplicated region for block: B:149:0x0327  */
    /* JADX WARN: Removed duplicated region for block: B:150:0x0315  */
    /* JADX WARN: Removed duplicated region for block: B:316:0x0535  */
    /* JADX WARN: Removed duplicated region for block: B:86:0x0264 A[LOOP:8: B:78:0x014a->B:86:0x0264, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:87:0x025e A[SYNTHETIC] */
    @Override // p005b.p199l.p200a.p201a.p245m1.AbstractC2259h
    /* renamed from: b */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final p005b.p199l.p200a.p201a.p245m1.C2260i mo2161b(p005b.p199l.p200a.p201a.AbstractC2397u[] r49, com.google.android.exoplayer2.source.TrackGroupArray r50, p005b.p199l.p200a.p201a.p227k1.InterfaceC2202y.a r51, p005b.p199l.p200a.p201a.AbstractC2404x0 r52) {
        /*
            Method dump skipped, instructions count: 2554
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p245m1.AbstractC2255d.mo2161b(b.l.a.a.u[], com.google.android.exoplayer2.source.TrackGroupArray, b.l.a.a.k1.y$a, b.l.a.a.x0):b.l.a.a.m1.i");
    }
}
