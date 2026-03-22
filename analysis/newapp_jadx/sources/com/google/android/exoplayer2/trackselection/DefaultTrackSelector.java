package com.google.android.exoplayer2.trackselection;

import android.content.res.Configuration;
import android.content.res.Resources;
import android.os.Parcel;
import android.os.Parcelable;
import android.text.TextUtils;
import android.util.SparseArray;
import android.util.SparseBooleanArray;
import androidx.annotation.Nullable;
import com.google.android.exoplayer2.Format;
import com.google.android.exoplayer2.source.TrackGroupArray;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;
import net.sourceforge.pinyin4j.ChineseToPinyinResource;
import p005b.p199l.p200a.p201a.p245m1.AbstractC2255d;
import p005b.p199l.p200a.p201a.p245m1.C2252a;
import p005b.p199l.p200a.p201a.p245m1.InterfaceC2257f;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* loaded from: classes.dex */
public class DefaultTrackSelector extends AbstractC2255d {

    /* renamed from: c */
    public static final int[] f9510c = new int[0];

    /* renamed from: d */
    public final InterfaceC2257f.b f9511d;

    /* renamed from: e */
    public final AtomicReference<Parameters> f9512e;

    public static final class SelectionOverride implements Parcelable {
        public static final Parcelable.Creator<SelectionOverride> CREATOR = new C3308a();

        /* renamed from: c */
        public final int f9536c;

        /* renamed from: e */
        public final int[] f9537e;

        /* renamed from: f */
        public final int f9538f;

        /* renamed from: g */
        public final int f9539g;

        /* renamed from: h */
        public final int f9540h;

        /* renamed from: com.google.android.exoplayer2.trackselection.DefaultTrackSelector$SelectionOverride$a */
        public static class C3308a implements Parcelable.Creator<SelectionOverride> {
            @Override // android.os.Parcelable.Creator
            public SelectionOverride createFromParcel(Parcel parcel) {
                return new SelectionOverride(parcel);
            }

            @Override // android.os.Parcelable.Creator
            public SelectionOverride[] newArray(int i2) {
                return new SelectionOverride[i2];
            }
        }

        public SelectionOverride(Parcel parcel) {
            this.f9536c = parcel.readInt();
            int readByte = parcel.readByte();
            this.f9538f = readByte;
            int[] iArr = new int[readByte];
            this.f9537e = iArr;
            parcel.readIntArray(iArr);
            this.f9539g = parcel.readInt();
            this.f9540h = parcel.readInt();
        }

        @Override // android.os.Parcelable
        public int describeContents() {
            return 0;
        }

        public boolean equals(@Nullable Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj == null || SelectionOverride.class != obj.getClass()) {
                return false;
            }
            SelectionOverride selectionOverride = (SelectionOverride) obj;
            return this.f9536c == selectionOverride.f9536c && Arrays.equals(this.f9537e, selectionOverride.f9537e) && this.f9539g == selectionOverride.f9539g && this.f9540h == selectionOverride.f9540h;
        }

        public int hashCode() {
            return ((((Arrays.hashCode(this.f9537e) + (this.f9536c * 31)) * 31) + this.f9539g) * 31) + this.f9540h;
        }

        @Override // android.os.Parcelable
        public void writeToParcel(Parcel parcel, int i2) {
            parcel.writeInt(this.f9536c);
            parcel.writeInt(this.f9537e.length);
            parcel.writeIntArray(this.f9537e);
            parcel.writeInt(this.f9539g);
            parcel.writeInt(this.f9540h);
        }
    }

    /* renamed from: com.google.android.exoplayer2.trackselection.DefaultTrackSelector$a */
    public static final class C3309a {

        /* renamed from: a */
        public final int f9541a;

        /* renamed from: b */
        public final int f9542b;

        /* renamed from: c */
        @Nullable
        public final String f9543c;

        public C3309a(int i2, int i3, @Nullable String str) {
            this.f9541a = i2;
            this.f9542b = i3;
            this.f9543c = str;
        }

        public boolean equals(@Nullable Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj == null || C3309a.class != obj.getClass()) {
                return false;
            }
            C3309a c3309a = (C3309a) obj;
            return this.f9541a == c3309a.f9541a && this.f9542b == c3309a.f9542b && TextUtils.equals(this.f9543c, c3309a.f9543c);
        }

        public int hashCode() {
            int i2 = ((this.f9541a * 31) + this.f9542b) * 31;
            String str = this.f9543c;
            return i2 + (str != null ? str.hashCode() : 0);
        }
    }

    /* renamed from: com.google.android.exoplayer2.trackselection.DefaultTrackSelector$b */
    public static final class C3310b implements Comparable<C3310b> {

        /* renamed from: c */
        public final boolean f9544c;

        /* renamed from: e */
        @Nullable
        public final String f9545e;

        /* renamed from: f */
        public final Parameters f9546f;

        /* renamed from: g */
        public final boolean f9547g;

        /* renamed from: h */
        public final int f9548h;

        /* renamed from: i */
        public final int f9549i;

        /* renamed from: j */
        public final int f9550j;

        /* renamed from: k */
        public final boolean f9551k;

        /* renamed from: l */
        public final int f9552l;

        /* renamed from: m */
        public final int f9553m;

        /* renamed from: n */
        public final int f9554n;

        public C3310b(Format format, Parameters parameters, int i2) {
            String[] strArr;
            this.f9546f = parameters;
            this.f9545e = DefaultTrackSelector.m4076j(format.f9233D);
            int i3 = 0;
            this.f9547g = DefaultTrackSelector.m4073g(i2, false);
            this.f9548h = DefaultTrackSelector.m4071e(format, parameters.f9564e, false);
            this.f9551k = (format.f9239f & 1) != 0;
            int i4 = format.f9258y;
            this.f9552l = i4;
            this.f9553m = format.f9259z;
            int i5 = format.f9241h;
            this.f9554n = i5;
            this.f9544c = (i5 == -1 || i5 <= parameters.f9531v) && (i4 == -1 || i4 <= parameters.f9530u);
            int i6 = C2344d0.f6035a;
            Configuration configuration = Resources.getSystem().getConfiguration();
            int i7 = C2344d0.f6035a;
            if (i7 >= 24) {
                strArr = C2344d0.m2316H(configuration.getLocales().toLanguageTags(), ChineseToPinyinResource.Field.COMMA);
            } else {
                String[] strArr2 = new String[1];
                Locale locale = configuration.locale;
                strArr2[0] = i7 >= 21 ? locale.toLanguageTag() : locale.toString();
                strArr = strArr2;
            }
            for (int i8 = 0; i8 < strArr.length; i8++) {
                strArr[i8] = C2344d0.m2348z(strArr[i8]);
            }
            int i9 = Integer.MAX_VALUE;
            int i10 = 0;
            while (true) {
                if (i10 >= strArr.length) {
                    break;
                }
                int m4071e = DefaultTrackSelector.m4071e(format, strArr[i10], false);
                if (m4071e > 0) {
                    i9 = i10;
                    i3 = m4071e;
                    break;
                }
                i10++;
            }
            this.f9549i = i9;
            this.f9550j = i3;
        }

        @Override // java.lang.Comparable
        /* renamed from: a, reason: merged with bridge method [inline-methods] */
        public int compareTo(C3310b c3310b) {
            int m4070d;
            boolean z = this.f9547g;
            if (z != c3310b.f9547g) {
                return z ? 1 : -1;
            }
            int i2 = this.f9548h;
            int i3 = c3310b.f9548h;
            if (i2 != i3) {
                return DefaultTrackSelector.m4069c(i2, i3);
            }
            boolean z2 = this.f9544c;
            if (z2 != c3310b.f9544c) {
                return z2 ? 1 : -1;
            }
            if (this.f9546f.f9514A && (m4070d = DefaultTrackSelector.m4070d(this.f9554n, c3310b.f9554n)) != 0) {
                return m4070d > 0 ? -1 : 1;
            }
            boolean z3 = this.f9551k;
            if (z3 != c3310b.f9551k) {
                return z3 ? 1 : -1;
            }
            int i4 = this.f9549i;
            int i5 = c3310b.f9549i;
            if (i4 != i5) {
                return -DefaultTrackSelector.m4069c(i4, i5);
            }
            int i6 = this.f9550j;
            int i7 = c3310b.f9550j;
            if (i6 != i7) {
                return DefaultTrackSelector.m4069c(i6, i7);
            }
            int i8 = (this.f9544c && this.f9547g) ? 1 : -1;
            int i9 = this.f9552l;
            int i10 = c3310b.f9552l;
            if (i9 != i10) {
                return DefaultTrackSelector.m4069c(i9, i10) * i8;
            }
            int i11 = this.f9553m;
            int i12 = c3310b.f9553m;
            if (i11 != i12) {
                return DefaultTrackSelector.m4069c(i11, i12) * i8;
            }
            if (C2344d0.m2323a(this.f9545e, c3310b.f9545e)) {
                return DefaultTrackSelector.m4069c(this.f9554n, c3310b.f9554n) * i8;
            }
            return 0;
        }
    }

    /* renamed from: com.google.android.exoplayer2.trackselection.DefaultTrackSelector$c */
    public static final class C3311c implements Comparable<C3311c> {

        /* renamed from: c */
        public final boolean f9555c;

        /* renamed from: e */
        public final boolean f9556e;

        /* renamed from: f */
        public final boolean f9557f;

        /* renamed from: g */
        public final boolean f9558g;

        /* renamed from: h */
        public final int f9559h;

        /* renamed from: i */
        public final int f9560i;

        /* renamed from: j */
        public final int f9561j;

        /* renamed from: k */
        public final boolean f9562k;

        public C3311c(Format format, Parameters parameters, int i2, @Nullable String str) {
            boolean z = false;
            this.f9556e = DefaultTrackSelector.m4073g(i2, false);
            int i3 = format.f9239f & (~parameters.f9568i);
            boolean z2 = (i3 & 1) != 0;
            this.f9557f = z2;
            boolean z3 = (i3 & 2) != 0;
            int m4071e = DefaultTrackSelector.m4071e(format, parameters.f9565f, parameters.f9567h);
            this.f9559h = m4071e;
            int bitCount = Integer.bitCount(format.f9240g & parameters.f9566g);
            this.f9560i = bitCount;
            this.f9562k = (format.f9240g & 1088) != 0;
            this.f9558g = (m4071e > 0 && !z3) || (m4071e == 0 && z3);
            int m4071e2 = DefaultTrackSelector.m4071e(format, str, DefaultTrackSelector.m4076j(str) == null);
            this.f9561j = m4071e2;
            if (m4071e > 0 || ((parameters.f9565f == null && bitCount > 0) || z2 || (z3 && m4071e2 > 0))) {
                z = true;
            }
            this.f9555c = z;
        }

        @Override // java.lang.Comparable
        /* renamed from: a, reason: merged with bridge method [inline-methods] */
        public int compareTo(C3311c c3311c) {
            boolean z;
            boolean z2 = this.f9556e;
            if (z2 != c3311c.f9556e) {
                return z2 ? 1 : -1;
            }
            int i2 = this.f9559h;
            int i3 = c3311c.f9559h;
            if (i2 != i3) {
                return DefaultTrackSelector.m4069c(i2, i3);
            }
            int i4 = this.f9560i;
            int i5 = c3311c.f9560i;
            if (i4 != i5) {
                return DefaultTrackSelector.m4069c(i4, i5);
            }
            boolean z3 = this.f9557f;
            if (z3 != c3311c.f9557f) {
                return z3 ? 1 : -1;
            }
            boolean z4 = this.f9558g;
            if (z4 != c3311c.f9558g) {
                return z4 ? 1 : -1;
            }
            int i6 = this.f9561j;
            int i7 = c3311c.f9561j;
            if (i6 != i7) {
                return DefaultTrackSelector.m4069c(i6, i7);
            }
            if (i4 != 0 || (z = this.f9562k) == c3311c.f9562k) {
                return 0;
            }
            return z ? -1 : 1;
        }
    }

    @Deprecated
    public DefaultTrackSelector() {
        C2252a.d dVar = new C2252a.d();
        Parameters parameters = Parameters.f9513j;
        this.f9511d = dVar;
        this.f9512e = new AtomicReference<>(parameters);
    }

    /* renamed from: c */
    public static int m4069c(int i2, int i3) {
        if (i2 > i3) {
            return 1;
        }
        return i3 > i2 ? -1 : 0;
    }

    /* renamed from: d */
    public static int m4070d(int i2, int i3) {
        if (i2 == -1) {
            return i3 == -1 ? 0 : -1;
        }
        if (i3 == -1) {
            return 1;
        }
        return i2 - i3;
    }

    /* renamed from: e */
    public static int m4071e(Format format, @Nullable String str, boolean z) {
        if (!TextUtils.isEmpty(str) && str.equals(format.f9233D)) {
            return 4;
        }
        String m4076j = m4076j(str);
        String m4076j2 = m4076j(format.f9233D);
        if (m4076j2 == null || m4076j == null) {
            return (z && m4076j2 == null) ? 1 : 0;
        }
        if (m4076j2.startsWith(m4076j) || m4076j.startsWith(m4076j2)) {
            return 3;
        }
        int i2 = C2344d0.f6035a;
        return m4076j2.split("-", 2)[0].equals(m4076j.split("-", 2)[0]) ? 2 : 0;
    }

    /* JADX WARN: Removed duplicated region for block: B:25:0x004d  */
    /* JADX WARN: Removed duplicated region for block: B:37:0x0057  */
    /* renamed from: f */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static java.util.List<java.lang.Integer> m4072f(com.google.android.exoplayer2.source.TrackGroup r12, int r13, int r14, boolean r15) {
        /*
            java.util.ArrayList r0 = new java.util.ArrayList
            int r1 = r12.f9393c
            r0.<init>(r1)
            r1 = 0
            r2 = 0
        L9:
            int r3 = r12.f9393c
            if (r2 >= r3) goto L17
            java.lang.Integer r3 = java.lang.Integer.valueOf(r2)
            r0.add(r3)
            int r2 = r2 + 1
            goto L9
        L17:
            r2 = 2147483647(0x7fffffff, float:NaN)
            if (r13 == r2) goto La6
            if (r14 != r2) goto L20
            goto La6
        L20:
            r3 = 0
            r4 = 2147483647(0x7fffffff, float:NaN)
        L24:
            int r5 = r12.f9393c
            r6 = 1
            if (r3 >= r5) goto L80
            com.google.android.exoplayer2.Format[] r5 = r12.f9394e
            r5 = r5[r3]
            int r7 = r5.f9250q
            if (r7 <= 0) goto L7d
            int r8 = r5.f9251r
            if (r8 <= 0) goto L7d
            if (r15 == 0) goto L45
            if (r7 <= r8) goto L3b
            r9 = 1
            goto L3c
        L3b:
            r9 = 0
        L3c:
            if (r13 <= r14) goto L3f
            goto L40
        L3f:
            r6 = 0
        L40:
            if (r9 == r6) goto L45
            r6 = r13
            r9 = r14
            goto L47
        L45:
            r9 = r13
            r6 = r14
        L47:
            int r10 = r7 * r6
            int r11 = r8 * r9
            if (r10 < r11) goto L57
            android.graphics.Point r6 = new android.graphics.Point
            int r7 = p005b.p199l.p200a.p201a.p250p1.C2344d0.m2327e(r11, r7)
            r6.<init>(r9, r7)
            goto L61
        L57:
            android.graphics.Point r7 = new android.graphics.Point
            int r8 = p005b.p199l.p200a.p201a.p250p1.C2344d0.m2327e(r10, r8)
            r7.<init>(r8, r6)
            r6 = r7
        L61:
            int r7 = r5.f9250q
            int r5 = r5.f9251r
            int r8 = r7 * r5
            int r9 = r6.x
            float r9 = (float) r9
            r10 = 1065017672(0x3f7ae148, float:0.98)
            float r9 = r9 * r10
            int r9 = (int) r9
            if (r7 < r9) goto L7d
            int r6 = r6.y
            float r6 = (float) r6
            float r6 = r6 * r10
            int r6 = (int) r6
            if (r5 < r6) goto L7d
            if (r8 >= r4) goto L7d
            r4 = r8
        L7d:
            int r3 = r3 + 1
            goto L24
        L80:
            if (r4 == r2) goto La6
            int r13 = r0.size()
            int r13 = r13 - r6
        L87:
            if (r13 < 0) goto La6
            java.lang.Object r14 = r0.get(r13)
            java.lang.Integer r14 = (java.lang.Integer) r14
            int r14 = r14.intValue()
            com.google.android.exoplayer2.Format[] r15 = r12.f9394e
            r14 = r15[r14]
            int r14 = r14.m4040M()
            r15 = -1
            if (r14 == r15) goto La0
            if (r14 <= r4) goto La3
        La0:
            r0.remove(r13)
        La3:
            int r13 = r13 + (-1)
            goto L87
        La6:
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.exoplayer2.trackselection.DefaultTrackSelector.m4072f(com.google.android.exoplayer2.source.TrackGroup, int, int, boolean):java.util.List");
    }

    /* renamed from: g */
    public static boolean m4073g(int i2, boolean z) {
        int i3 = i2 & 7;
        return i3 == 4 || (z && i3 == 3);
    }

    /* renamed from: h */
    public static boolean m4074h(Format format, int i2, C3309a c3309a, int i3, boolean z, boolean z2, boolean z3) {
        int i4;
        String str;
        int i5;
        if (!m4073g(i2, false)) {
            return false;
        }
        int i6 = format.f9241h;
        if (i6 != -1 && i6 > i3) {
            return false;
        }
        if (!z3 && ((i5 = format.f9258y) == -1 || i5 != c3309a.f9541a)) {
            return false;
        }
        if (z || ((str = format.f9245l) != null && TextUtils.equals(str, c3309a.f9543c))) {
            return z2 || ((i4 = format.f9259z) != -1 && i4 == c3309a.f9542b);
        }
        return false;
    }

    /* renamed from: i */
    public static boolean m4075i(Format format, @Nullable String str, int i2, int i3, int i4, int i5, int i6, int i7) {
        if (!m4073g(i2, false) || (i2 & i3) == 0) {
            return false;
        }
        if (str != null && !C2344d0.m2323a(format.f9245l, str)) {
            return false;
        }
        int i8 = format.f9250q;
        if (i8 != -1 && i8 > i4) {
            return false;
        }
        int i9 = format.f9251r;
        if (i9 != -1 && i9 > i5) {
            return false;
        }
        float f2 = format.f9252s;
        if (f2 != -1.0f && f2 > i6) {
            return false;
        }
        int i10 = format.f9241h;
        return i10 == -1 || i10 <= i7;
    }

    @Nullable
    /* renamed from: j */
    public static String m4076j(@Nullable String str) {
        if (TextUtils.isEmpty(str) || TextUtils.equals(str, "und")) {
            return null;
        }
        return str;
    }

    public static final class Parameters extends TrackSelectionParameters {

        /* renamed from: A */
        public final boolean f9514A;

        /* renamed from: B */
        public final boolean f9515B;

        /* renamed from: C */
        public final boolean f9516C;

        /* renamed from: D */
        public final int f9517D;

        /* renamed from: E */
        public final SparseArray<Map<TrackGroupArray, SelectionOverride>> f9518E;

        /* renamed from: F */
        public final SparseBooleanArray f9519F;

        /* renamed from: k */
        public final int f9520k;

        /* renamed from: l */
        public final int f9521l;

        /* renamed from: m */
        public final int f9522m;

        /* renamed from: n */
        public final int f9523n;

        /* renamed from: o */
        public final boolean f9524o;

        /* renamed from: p */
        public final boolean f9525p;

        /* renamed from: q */
        public final boolean f9526q;

        /* renamed from: r */
        public final int f9527r;

        /* renamed from: s */
        public final int f9528s;

        /* renamed from: t */
        public final boolean f9529t;

        /* renamed from: u */
        public final int f9530u;

        /* renamed from: v */
        public final int f9531v;

        /* renamed from: w */
        public final boolean f9532w;

        /* renamed from: x */
        public final boolean f9533x;

        /* renamed from: y */
        public final boolean f9534y;

        /* renamed from: z */
        public final boolean f9535z;

        /* renamed from: j */
        public static final Parameters f9513j = new Parameters(Integer.MAX_VALUE, Integer.MAX_VALUE, Integer.MAX_VALUE, Integer.MAX_VALUE, true, false, true, Integer.MAX_VALUE, Integer.MAX_VALUE, true, null, Integer.MAX_VALUE, Integer.MAX_VALUE, true, false, false, false, null, 0, false, 0, false, false, true, 0, new SparseArray(), new SparseBooleanArray());
        public static final Parcelable.Creator<Parameters> CREATOR = new C3307a();

        /* renamed from: com.google.android.exoplayer2.trackselection.DefaultTrackSelector$Parameters$a */
        public static class C3307a implements Parcelable.Creator<Parameters> {
            @Override // android.os.Parcelable.Creator
            public Parameters createFromParcel(Parcel parcel) {
                return new Parameters(parcel);
            }

            @Override // android.os.Parcelable.Creator
            public Parameters[] newArray(int i2) {
                return new Parameters[i2];
            }
        }

        public Parameters(int i2, int i3, int i4, int i5, boolean z, boolean z2, boolean z3, int i6, int i7, boolean z4, @Nullable String str, int i8, int i9, boolean z5, boolean z6, boolean z7, boolean z8, @Nullable String str2, int i10, boolean z9, int i11, boolean z10, boolean z11, boolean z12, int i12, SparseArray<Map<TrackGroupArray, SelectionOverride>> sparseArray, SparseBooleanArray sparseBooleanArray) {
            super(null, null, i10, z9, i11);
            this.f9520k = i2;
            this.f9521l = i3;
            this.f9522m = i4;
            this.f9523n = i5;
            this.f9524o = z;
            this.f9525p = z2;
            this.f9526q = z3;
            this.f9527r = i6;
            this.f9528s = i7;
            this.f9529t = z4;
            this.f9530u = i8;
            this.f9531v = i9;
            this.f9532w = z5;
            this.f9533x = z6;
            this.f9534y = z7;
            this.f9535z = z8;
            this.f9514A = z10;
            this.f9515B = z11;
            this.f9516C = z12;
            this.f9517D = i12;
            this.f9518E = sparseArray;
            this.f9519F = sparseBooleanArray;
        }

        @Override // com.google.android.exoplayer2.trackselection.TrackSelectionParameters, android.os.Parcelable
        public int describeContents() {
            return 0;
        }

        /* JADX WARN: Removed duplicated region for block: B:55:0x00b6  */
        /* JADX WARN: Removed duplicated region for block: B:59:? A[RETURN, SYNTHETIC] */
        /* JADX WARN: Removed duplicated region for block: B:79:0x011e A[LOOP:0: B:61:0x00c7->B:79:0x011e, LOOP_END] */
        /* JADX WARN: Removed duplicated region for block: B:80:0x00c4 A[SYNTHETIC] */
        @Override // com.google.android.exoplayer2.trackselection.TrackSelectionParameters
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public boolean equals(@androidx.annotation.Nullable java.lang.Object r11) {
            /*
                Method dump skipped, instructions count: 296
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: com.google.android.exoplayer2.trackselection.DefaultTrackSelector.Parameters.equals(java.lang.Object):boolean");
        }

        @Override // com.google.android.exoplayer2.trackselection.TrackSelectionParameters
        public int hashCode() {
            return (((((((((((((((((((((((((((((((((((((((super.hashCode() * 31) + this.f9520k) * 31) + this.f9521l) * 31) + this.f9522m) * 31) + this.f9523n) * 31) + (this.f9524o ? 1 : 0)) * 31) + (this.f9525p ? 1 : 0)) * 31) + (this.f9526q ? 1 : 0)) * 31) + (this.f9529t ? 1 : 0)) * 31) + this.f9527r) * 31) + this.f9528s) * 31) + this.f9530u) * 31) + this.f9531v) * 31) + (this.f9532w ? 1 : 0)) * 31) + (this.f9533x ? 1 : 0)) * 31) + (this.f9534y ? 1 : 0)) * 31) + (this.f9535z ? 1 : 0)) * 31) + (this.f9514A ? 1 : 0)) * 31) + (this.f9515B ? 1 : 0)) * 31) + (this.f9516C ? 1 : 0)) * 31) + this.f9517D;
        }

        @Override // com.google.android.exoplayer2.trackselection.TrackSelectionParameters, android.os.Parcelable
        public void writeToParcel(Parcel parcel, int i2) {
            super.writeToParcel(parcel, i2);
            parcel.writeInt(this.f9520k);
            parcel.writeInt(this.f9521l);
            parcel.writeInt(this.f9522m);
            parcel.writeInt(this.f9523n);
            parcel.writeInt(this.f9524o ? 1 : 0);
            parcel.writeInt(this.f9525p ? 1 : 0);
            parcel.writeInt(this.f9526q ? 1 : 0);
            parcel.writeInt(this.f9527r);
            parcel.writeInt(this.f9528s);
            parcel.writeInt(this.f9529t ? 1 : 0);
            parcel.writeInt(this.f9530u);
            parcel.writeInt(this.f9531v);
            parcel.writeInt(this.f9532w ? 1 : 0);
            parcel.writeInt(this.f9533x ? 1 : 0);
            parcel.writeInt(this.f9534y ? 1 : 0);
            parcel.writeInt(this.f9535z ? 1 : 0);
            parcel.writeInt(this.f9514A ? 1 : 0);
            parcel.writeInt(this.f9515B ? 1 : 0);
            parcel.writeInt(this.f9516C ? 1 : 0);
            parcel.writeInt(this.f9517D);
            SparseArray<Map<TrackGroupArray, SelectionOverride>> sparseArray = this.f9518E;
            int size = sparseArray.size();
            parcel.writeInt(size);
            for (int i3 = 0; i3 < size; i3++) {
                int keyAt = sparseArray.keyAt(i3);
                Map<TrackGroupArray, SelectionOverride> valueAt = sparseArray.valueAt(i3);
                int size2 = valueAt.size();
                parcel.writeInt(keyAt);
                parcel.writeInt(size2);
                for (Map.Entry<TrackGroupArray, SelectionOverride> entry : valueAt.entrySet()) {
                    parcel.writeParcelable(entry.getKey(), 0);
                    parcel.writeParcelable(entry.getValue(), 0);
                }
            }
            parcel.writeSparseBooleanArray(this.f9519F);
        }

        public Parameters(Parcel parcel) {
            super(parcel);
            this.f9520k = parcel.readInt();
            this.f9521l = parcel.readInt();
            this.f9522m = parcel.readInt();
            this.f9523n = parcel.readInt();
            this.f9524o = parcel.readInt() != 0;
            this.f9525p = parcel.readInt() != 0;
            this.f9526q = parcel.readInt() != 0;
            this.f9527r = parcel.readInt();
            this.f9528s = parcel.readInt();
            this.f9529t = parcel.readInt() != 0;
            this.f9530u = parcel.readInt();
            this.f9531v = parcel.readInt();
            this.f9532w = parcel.readInt() != 0;
            this.f9533x = parcel.readInt() != 0;
            this.f9534y = parcel.readInt() != 0;
            this.f9535z = parcel.readInt() != 0;
            this.f9514A = parcel.readInt() != 0;
            this.f9515B = parcel.readInt() != 0;
            this.f9516C = parcel.readInt() != 0;
            this.f9517D = parcel.readInt();
            int readInt = parcel.readInt();
            SparseArray<Map<TrackGroupArray, SelectionOverride>> sparseArray = new SparseArray<>(readInt);
            for (int i2 = 0; i2 < readInt; i2++) {
                int readInt2 = parcel.readInt();
                int readInt3 = parcel.readInt();
                HashMap hashMap = new HashMap(readInt3);
                for (int i3 = 0; i3 < readInt3; i3++) {
                    Parcelable readParcelable = parcel.readParcelable(TrackGroupArray.class.getClassLoader());
                    Objects.requireNonNull(readParcelable);
                    hashMap.put((TrackGroupArray) readParcelable, (SelectionOverride) parcel.readParcelable(SelectionOverride.class.getClassLoader()));
                }
                sparseArray.put(readInt2, hashMap);
            }
            this.f9518E = sparseArray;
            this.f9519F = parcel.readSparseBooleanArray();
        }
    }
}
