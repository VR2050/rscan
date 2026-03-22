package com.google.android.exoplayer2;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.annotation.Nullable;
import com.google.android.exoplayer2.drm.DrmInitData;
import com.google.android.exoplayer2.metadata.Metadata;
import com.google.android.exoplayer2.video.ColorInfo;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p205d1.InterfaceC1956g;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* loaded from: classes.dex */
public final class Format implements Parcelable {
    public static final Parcelable.Creator<Format> CREATOR = new C3259a();

    /* renamed from: A */
    public final int f9230A;

    /* renamed from: B */
    public final int f9231B;

    /* renamed from: C */
    public final int f9232C;

    /* renamed from: D */
    @Nullable
    public final String f9233D;

    /* renamed from: E */
    public final int f9234E;

    /* renamed from: F */
    @Nullable
    public final Class<? extends InterfaceC1956g> f9235F;

    /* renamed from: G */
    public int f9236G;

    /* renamed from: c */
    @Nullable
    public final String f9237c;

    /* renamed from: e */
    @Nullable
    public final String f9238e;

    /* renamed from: f */
    public final int f9239f;

    /* renamed from: g */
    public final int f9240g;

    /* renamed from: h */
    public final int f9241h;

    /* renamed from: i */
    @Nullable
    public final String f9242i;

    /* renamed from: j */
    @Nullable
    public final Metadata f9243j;

    /* renamed from: k */
    @Nullable
    public final String f9244k;

    /* renamed from: l */
    @Nullable
    public final String f9245l;

    /* renamed from: m */
    public final int f9246m;

    /* renamed from: n */
    public final List<byte[]> f9247n;

    /* renamed from: o */
    @Nullable
    public final DrmInitData f9248o;

    /* renamed from: p */
    public final long f9249p;

    /* renamed from: q */
    public final int f9250q;

    /* renamed from: r */
    public final int f9251r;

    /* renamed from: s */
    public final float f9252s;

    /* renamed from: t */
    public final int f9253t;

    /* renamed from: u */
    public final float f9254u;

    /* renamed from: v */
    public final int f9255v;

    /* renamed from: w */
    @Nullable
    public final byte[] f9256w;

    /* renamed from: x */
    @Nullable
    public final ColorInfo f9257x;

    /* renamed from: y */
    public final int f9258y;

    /* renamed from: z */
    public final int f9259z;

    /* renamed from: com.google.android.exoplayer2.Format$a */
    public static class C3259a implements Parcelable.Creator<Format> {
        @Override // android.os.Parcelable.Creator
        public Format createFromParcel(Parcel parcel) {
            return new Format(parcel);
        }

        @Override // android.os.Parcelable.Creator
        public Format[] newArray(int i2) {
            return new Format[i2];
        }
    }

    public Format(@Nullable String str, @Nullable String str2, int i2, int i3, int i4, @Nullable String str3, @Nullable Metadata metadata, @Nullable String str4, @Nullable String str5, int i5, @Nullable List<byte[]> list, @Nullable DrmInitData drmInitData, long j2, int i6, int i7, float f2, int i8, float f3, @Nullable byte[] bArr, int i9, @Nullable ColorInfo colorInfo, int i10, int i11, int i12, int i13, int i14, @Nullable String str6, int i15, @Nullable Class<? extends InterfaceC1956g> cls) {
        this.f9237c = str;
        this.f9238e = str2;
        this.f9239f = i2;
        this.f9240g = i3;
        this.f9241h = i4;
        this.f9242i = str3;
        this.f9243j = metadata;
        this.f9244k = str4;
        this.f9245l = str5;
        this.f9246m = i5;
        this.f9247n = list == null ? Collections.emptyList() : list;
        this.f9248o = drmInitData;
        this.f9249p = j2;
        this.f9250q = i6;
        this.f9251r = i7;
        this.f9252s = f2;
        int i16 = i8;
        this.f9253t = i16 == -1 ? 0 : i16;
        this.f9254u = f3 == -1.0f ? 1.0f : f3;
        this.f9256w = bArr;
        this.f9255v = i9;
        this.f9257x = colorInfo;
        this.f9258y = i10;
        this.f9259z = i11;
        this.f9230A = i12;
        int i17 = i13;
        this.f9231B = i17 == -1 ? 0 : i17;
        this.f9232C = i14 != -1 ? i14 : 0;
        this.f9233D = C2344d0.m2348z(str6);
        this.f9234E = i15;
        this.f9235F = cls;
    }

    /* renamed from: A */
    public static Format m4024A(@Nullable String str, @Nullable String str2, @Nullable String str3, int i2, int i3, int i4, int i5, @Nullable List<byte[]> list, @Nullable DrmInitData drmInitData, int i6, @Nullable String str4) {
        return m4039z(str, str2, null, i2, i3, i4, i5, -1, list, drmInitData, i6, str4);
    }

    /* renamed from: B */
    public static Format m4025B(@Nullable String str, @Nullable String str2, @Nullable String str3, @Nullable String str4, @Nullable String str5, int i2, int i3, int i4, @Nullable String str6) {
        return new Format(str, str2, i3, i4, i2, str5, null, str3, str4, -1, null, null, Long.MAX_VALUE, -1, -1, -1.0f, -1, -1.0f, null, -1, null, -1, -1, -1, -1, -1, str6, -1, null);
    }

    /* renamed from: C */
    public static Format m4026C(@Nullable String str, @Nullable String str2, @Nullable String str3, int i2, int i3, @Nullable List<byte[]> list, @Nullable String str4, @Nullable DrmInitData drmInitData) {
        return new Format(str, null, i3, 0, i2, null, null, null, str2, -1, list, drmInitData, Long.MAX_VALUE, -1, -1, -1.0f, -1, -1.0f, null, -1, null, -1, -1, -1, -1, -1, str4, -1, null);
    }

    /* renamed from: D */
    public static Format m4027D(@Nullable String str, @Nullable String str2, long j2) {
        return new Format(str, null, 0, 0, -1, null, null, null, str2, -1, null, null, j2, -1, -1, -1.0f, -1, -1.0f, null, -1, null, -1, -1, -1, -1, -1, null, -1, null);
    }

    /* renamed from: E */
    public static Format m4028E(@Nullable String str, @Nullable String str2, @Nullable String str3, int i2, @Nullable DrmInitData drmInitData) {
        return new Format(str, null, 0, 0, i2, null, null, null, str2, -1, null, null, Long.MAX_VALUE, -1, -1, -1.0f, -1, -1.0f, null, -1, null, -1, -1, -1, -1, -1, null, -1, null);
    }

    /* renamed from: F */
    public static Format m4029F(@Nullable String str, @Nullable String str2, @Nullable String str3, @Nullable String str4, @Nullable String str5, int i2, int i3, int i4, @Nullable String str6) {
        return m4030G(str, str2, str3, str4, null, i2, i3, i4, str6, -1);
    }

    /* renamed from: G */
    public static Format m4030G(@Nullable String str, @Nullable String str2, @Nullable String str3, @Nullable String str4, @Nullable String str5, int i2, int i3, int i4, @Nullable String str6, int i5) {
        return new Format(str, str2, i3, i4, i2, str5, null, str3, str4, -1, null, null, Long.MAX_VALUE, -1, -1, -1.0f, -1, -1.0f, null, -1, null, -1, -1, -1, -1, -1, str6, i5, null);
    }

    /* renamed from: H */
    public static Format m4031H(@Nullable String str, @Nullable String str2, int i2, @Nullable String str3, @Nullable DrmInitData drmInitData) {
        return m4032I(str, str2, null, -1, i2, str3, -1, drmInitData, Long.MAX_VALUE, Collections.emptyList());
    }

    /* renamed from: I */
    public static Format m4032I(@Nullable String str, @Nullable String str2, @Nullable String str3, int i2, int i3, @Nullable String str4, int i4, @Nullable DrmInitData drmInitData, long j2, @Nullable List<byte[]> list) {
        return new Format(str, null, i3, 0, i2, str3, null, null, str2, -1, list, drmInitData, j2, -1, -1, -1.0f, -1, -1.0f, null, -1, null, -1, -1, -1, -1, -1, str4, i4, null);
    }

    /* renamed from: J */
    public static Format m4033J(@Nullable String str, @Nullable String str2, @Nullable String str3, @Nullable String str4, @Nullable String str5, @Nullable Metadata metadata, int i2, int i3, int i4, float f2, @Nullable List<byte[]> list, int i5, int i6) {
        return new Format(str, str2, i5, i6, i2, str5, metadata, str3, str4, -1, list, null, Long.MAX_VALUE, i3, i4, f2, -1, -1.0f, null, -1, null, -1, -1, -1, -1, -1, null, -1, null);
    }

    /* renamed from: K */
    public static Format m4034K(@Nullable String str, @Nullable String str2, @Nullable String str3, int i2, int i3, int i4, int i5, float f2, @Nullable List<byte[]> list, int i6, float f3, @Nullable DrmInitData drmInitData) {
        return m4035L(str, str2, str3, i2, i3, i4, i5, f2, list, i6, f3, null, -1, null, null);
    }

    /* renamed from: L */
    public static Format m4035L(@Nullable String str, @Nullable String str2, @Nullable String str3, int i2, int i3, int i4, int i5, float f2, @Nullable List<byte[]> list, int i6, float f3, @Nullable byte[] bArr, int i7, @Nullable ColorInfo colorInfo, @Nullable DrmInitData drmInitData) {
        return new Format(str, null, 0, 0, i2, str3, null, null, str2, i3, list, drmInitData, Long.MAX_VALUE, i4, i5, f2, i6, f3, bArr, i7, colorInfo, -1, -1, -1, -1, -1, null, -1, null);
    }

    /* renamed from: O */
    public static String m4036O(@Nullable Format format) {
        if (format == null) {
            return "null";
        }
        StringBuilder m586H = C1499a.m586H("id=");
        m586H.append(format.f9237c);
        m586H.append(", mimeType=");
        m586H.append(format.f9245l);
        if (format.f9241h != -1) {
            m586H.append(", bitrate=");
            m586H.append(format.f9241h);
        }
        if (format.f9242i != null) {
            m586H.append(", codecs=");
            m586H.append(format.f9242i);
        }
        if (format.f9250q != -1 && format.f9251r != -1) {
            m586H.append(", res=");
            m586H.append(format.f9250q);
            m586H.append("x");
            m586H.append(format.f9251r);
        }
        if (format.f9252s != -1.0f) {
            m586H.append(", fps=");
            m586H.append(format.f9252s);
        }
        if (format.f9258y != -1) {
            m586H.append(", channels=");
            m586H.append(format.f9258y);
        }
        if (format.f9259z != -1) {
            m586H.append(", sample_rate=");
            m586H.append(format.f9259z);
        }
        if (format.f9233D != null) {
            m586H.append(", language=");
            m586H.append(format.f9233D);
        }
        if (format.f9238e != null) {
            m586H.append(", label=");
            m586H.append(format.f9238e);
        }
        return m586H.toString();
    }

    /* renamed from: x */
    public static Format m4037x(@Nullable String str, @Nullable String str2, @Nullable String str3, @Nullable String str4, @Nullable String str5, @Nullable Metadata metadata, int i2, int i3, int i4, @Nullable List<byte[]> list, int i5, int i6, @Nullable String str6) {
        return new Format(str, str2, i5, i6, i2, str5, metadata, str3, str4, -1, list, null, Long.MAX_VALUE, -1, -1, -1.0f, -1, -1.0f, null, -1, null, i3, i4, -1, -1, -1, str6, -1, null);
    }

    /* renamed from: y */
    public static Format m4038y(@Nullable String str, @Nullable String str2, @Nullable String str3, int i2, int i3, int i4, int i5, int i6, int i7, int i8, @Nullable List<byte[]> list, @Nullable DrmInitData drmInitData, int i9, @Nullable String str4, @Nullable Metadata metadata) {
        return new Format(str, null, i9, 0, i2, str3, metadata, null, str2, i3, list, drmInitData, Long.MAX_VALUE, -1, -1, -1.0f, -1, -1.0f, null, -1, null, i4, i5, i6, i7, i8, str4, -1, null);
    }

    /* renamed from: z */
    public static Format m4039z(@Nullable String str, @Nullable String str2, @Nullable String str3, int i2, int i3, int i4, int i5, int i6, @Nullable List<byte[]> list, @Nullable DrmInitData drmInitData, int i7, @Nullable String str4) {
        return m4038y(str, str2, str3, i2, i3, i4, i5, i6, -1, -1, list, drmInitData, i7, str4, null);
    }

    /* renamed from: M */
    public int m4040M() {
        int i2;
        int i3 = this.f9250q;
        if (i3 == -1 || (i2 = this.f9251r) == -1) {
            return -1;
        }
        return i3 * i2;
    }

    /* renamed from: N */
    public boolean m4041N(Format format) {
        if (this.f9247n.size() != format.f9247n.size()) {
            return false;
        }
        for (int i2 = 0; i2 < this.f9247n.size(); i2++) {
            if (!Arrays.equals(this.f9247n.get(i2), format.f9247n.get(i2))) {
                return false;
            }
        }
        return true;
    }

    /* renamed from: b */
    public Format m4042b(@Nullable DrmInitData drmInitData, @Nullable Metadata metadata) {
        if (drmInitData == this.f9248o && metadata == this.f9243j) {
            return this;
        }
        return new Format(this.f9237c, this.f9238e, this.f9239f, this.f9240g, this.f9241h, this.f9242i, metadata, this.f9244k, this.f9245l, this.f9246m, this.f9247n, drmInitData, this.f9249p, this.f9250q, this.f9251r, this.f9252s, this.f9253t, this.f9254u, this.f9256w, this.f9255v, this.f9257x, this.f9258y, this.f9259z, this.f9230A, this.f9231B, this.f9232C, this.f9233D, this.f9234E, this.f9235F);
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    /* renamed from: e */
    public Format m4043e(@Nullable Class<? extends InterfaceC1956g> cls) {
        return new Format(this.f9237c, this.f9238e, this.f9239f, this.f9240g, this.f9241h, this.f9242i, this.f9243j, this.f9244k, this.f9245l, this.f9246m, this.f9247n, this.f9248o, this.f9249p, this.f9250q, this.f9251r, this.f9252s, this.f9253t, this.f9254u, this.f9256w, this.f9255v, this.f9257x, this.f9258y, this.f9259z, this.f9230A, this.f9231B, this.f9232C, this.f9233D, this.f9234E, cls);
    }

    public boolean equals(@Nullable Object obj) {
        int i2;
        if (this == obj) {
            return true;
        }
        if (obj == null || Format.class != obj.getClass()) {
            return false;
        }
        Format format = (Format) obj;
        int i3 = this.f9236G;
        return (i3 == 0 || (i2 = format.f9236G) == 0 || i3 == i2) && this.f9239f == format.f9239f && this.f9240g == format.f9240g && this.f9241h == format.f9241h && this.f9246m == format.f9246m && this.f9249p == format.f9249p && this.f9250q == format.f9250q && this.f9251r == format.f9251r && this.f9253t == format.f9253t && this.f9255v == format.f9255v && this.f9258y == format.f9258y && this.f9259z == format.f9259z && this.f9230A == format.f9230A && this.f9231B == format.f9231B && this.f9232C == format.f9232C && this.f9234E == format.f9234E && Float.compare(this.f9252s, format.f9252s) == 0 && Float.compare(this.f9254u, format.f9254u) == 0 && C2344d0.m2323a(this.f9235F, format.f9235F) && C2344d0.m2323a(this.f9237c, format.f9237c) && C2344d0.m2323a(this.f9238e, format.f9238e) && C2344d0.m2323a(this.f9242i, format.f9242i) && C2344d0.m2323a(this.f9244k, format.f9244k) && C2344d0.m2323a(this.f9245l, format.f9245l) && C2344d0.m2323a(this.f9233D, format.f9233D) && Arrays.equals(this.f9256w, format.f9256w) && C2344d0.m2323a(this.f9243j, format.f9243j) && C2344d0.m2323a(this.f9257x, format.f9257x) && C2344d0.m2323a(this.f9248o, format.f9248o) && m4041N(format);
    }

    public int hashCode() {
        if (this.f9236G == 0) {
            String str = this.f9237c;
            int hashCode = (527 + (str == null ? 0 : str.hashCode())) * 31;
            String str2 = this.f9238e;
            int hashCode2 = (((((((hashCode + (str2 != null ? str2.hashCode() : 0)) * 31) + this.f9239f) * 31) + this.f9240g) * 31) + this.f9241h) * 31;
            String str3 = this.f9242i;
            int hashCode3 = (hashCode2 + (str3 == null ? 0 : str3.hashCode())) * 31;
            Metadata metadata = this.f9243j;
            int hashCode4 = (hashCode3 + (metadata == null ? 0 : metadata.hashCode())) * 31;
            String str4 = this.f9244k;
            int hashCode5 = (hashCode4 + (str4 == null ? 0 : str4.hashCode())) * 31;
            String str5 = this.f9245l;
            int floatToIntBits = (((((((((((((Float.floatToIntBits(this.f9254u) + ((((Float.floatToIntBits(this.f9252s) + ((((((((((hashCode5 + (str5 == null ? 0 : str5.hashCode())) * 31) + this.f9246m) * 31) + ((int) this.f9249p)) * 31) + this.f9250q) * 31) + this.f9251r) * 31)) * 31) + this.f9253t) * 31)) * 31) + this.f9255v) * 31) + this.f9258y) * 31) + this.f9259z) * 31) + this.f9230A) * 31) + this.f9231B) * 31) + this.f9232C) * 31;
            String str6 = this.f9233D;
            int hashCode6 = (((floatToIntBits + (str6 == null ? 0 : str6.hashCode())) * 31) + this.f9234E) * 31;
            Class<? extends InterfaceC1956g> cls = this.f9235F;
            this.f9236G = hashCode6 + (cls != null ? cls.hashCode() : 0);
        }
        return this.f9236G;
    }

    /* renamed from: k */
    public Format m4044k(float f2) {
        return new Format(this.f9237c, this.f9238e, this.f9239f, this.f9240g, this.f9241h, this.f9242i, this.f9243j, this.f9244k, this.f9245l, this.f9246m, this.f9247n, this.f9248o, this.f9249p, this.f9250q, this.f9251r, f2, this.f9253t, this.f9254u, this.f9256w, this.f9255v, this.f9257x, this.f9258y, this.f9259z, this.f9230A, this.f9231B, this.f9232C, this.f9233D, this.f9234E, this.f9235F);
    }

    /* renamed from: o */
    public Format m4045o(int i2, int i3) {
        return new Format(this.f9237c, this.f9238e, this.f9239f, this.f9240g, this.f9241h, this.f9242i, this.f9243j, this.f9244k, this.f9245l, this.f9246m, this.f9247n, this.f9248o, this.f9249p, this.f9250q, this.f9251r, this.f9252s, this.f9253t, this.f9254u, this.f9256w, this.f9255v, this.f9257x, this.f9258y, this.f9259z, this.f9230A, i2, i3, this.f9233D, this.f9234E, this.f9235F);
    }

    /* JADX WARN: Removed duplicated region for block: B:22:0x0048  */
    /* JADX WARN: Removed duplicated region for block: B:30:0x007a  */
    /* JADX WARN: Removed duplicated region for block: B:40:0x0093  */
    /* JADX WARN: Removed duplicated region for block: B:65:0x00e4  */
    /* JADX WARN: Removed duplicated region for block: B:68:0x00e6  */
    /* JADX WARN: Removed duplicated region for block: B:69:0x0090  */
    /* JADX WARN: Removed duplicated region for block: B:71:0x004b  */
    /* renamed from: q */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public com.google.android.exoplayer2.Format m4046q(com.google.android.exoplayer2.Format r36) {
        /*
            Method dump skipped, instructions count: 329
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.exoplayer2.Format.m4046q(com.google.android.exoplayer2.Format):com.google.android.exoplayer2.Format");
    }

    public String toString() {
        StringBuilder m586H = C1499a.m586H("Format(");
        m586H.append(this.f9237c);
        m586H.append(", ");
        m586H.append(this.f9238e);
        m586H.append(", ");
        m586H.append(this.f9244k);
        m586H.append(", ");
        m586H.append(this.f9245l);
        m586H.append(", ");
        m586H.append(this.f9242i);
        m586H.append(", ");
        m586H.append(this.f9241h);
        m586H.append(", ");
        m586H.append(this.f9233D);
        m586H.append(", [");
        m586H.append(this.f9250q);
        m586H.append(", ");
        m586H.append(this.f9251r);
        m586H.append(", ");
        m586H.append(this.f9252s);
        m586H.append("], [");
        m586H.append(this.f9258y);
        m586H.append(", ");
        return C1499a.m580B(m586H, this.f9259z, "])");
    }

    /* renamed from: w */
    public Format m4047w(long j2) {
        return new Format(this.f9237c, this.f9238e, this.f9239f, this.f9240g, this.f9241h, this.f9242i, this.f9243j, this.f9244k, this.f9245l, this.f9246m, this.f9247n, this.f9248o, j2, this.f9250q, this.f9251r, this.f9252s, this.f9253t, this.f9254u, this.f9256w, this.f9255v, this.f9257x, this.f9258y, this.f9259z, this.f9230A, this.f9231B, this.f9232C, this.f9233D, this.f9234E, this.f9235F);
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int i2) {
        parcel.writeString(this.f9237c);
        parcel.writeString(this.f9238e);
        parcel.writeInt(this.f9239f);
        parcel.writeInt(this.f9240g);
        parcel.writeInt(this.f9241h);
        parcel.writeString(this.f9242i);
        parcel.writeParcelable(this.f9243j, 0);
        parcel.writeString(this.f9244k);
        parcel.writeString(this.f9245l);
        parcel.writeInt(this.f9246m);
        int size = this.f9247n.size();
        parcel.writeInt(size);
        for (int i3 = 0; i3 < size; i3++) {
            parcel.writeByteArray(this.f9247n.get(i3));
        }
        parcel.writeParcelable(this.f9248o, 0);
        parcel.writeLong(this.f9249p);
        parcel.writeInt(this.f9250q);
        parcel.writeInt(this.f9251r);
        parcel.writeFloat(this.f9252s);
        parcel.writeInt(this.f9253t);
        parcel.writeFloat(this.f9254u);
        int i4 = this.f9256w != null ? 1 : 0;
        int i5 = C2344d0.f6035a;
        parcel.writeInt(i4);
        byte[] bArr = this.f9256w;
        if (bArr != null) {
            parcel.writeByteArray(bArr);
        }
        parcel.writeInt(this.f9255v);
        parcel.writeParcelable(this.f9257x, i2);
        parcel.writeInt(this.f9258y);
        parcel.writeInt(this.f9259z);
        parcel.writeInt(this.f9230A);
        parcel.writeInt(this.f9231B);
        parcel.writeInt(this.f9232C);
        parcel.writeString(this.f9233D);
        parcel.writeInt(this.f9234E);
    }

    public Format(Parcel parcel) {
        this.f9237c = parcel.readString();
        this.f9238e = parcel.readString();
        this.f9239f = parcel.readInt();
        this.f9240g = parcel.readInt();
        this.f9241h = parcel.readInt();
        this.f9242i = parcel.readString();
        this.f9243j = (Metadata) parcel.readParcelable(Metadata.class.getClassLoader());
        this.f9244k = parcel.readString();
        this.f9245l = parcel.readString();
        this.f9246m = parcel.readInt();
        int readInt = parcel.readInt();
        this.f9247n = new ArrayList(readInt);
        for (int i2 = 0; i2 < readInt; i2++) {
            this.f9247n.add(parcel.createByteArray());
        }
        this.f9248o = (DrmInitData) parcel.readParcelable(DrmInitData.class.getClassLoader());
        this.f9249p = parcel.readLong();
        this.f9250q = parcel.readInt();
        this.f9251r = parcel.readInt();
        this.f9252s = parcel.readFloat();
        this.f9253t = parcel.readInt();
        this.f9254u = parcel.readFloat();
        int i3 = C2344d0.f6035a;
        this.f9256w = parcel.readInt() != 0 ? parcel.createByteArray() : null;
        this.f9255v = parcel.readInt();
        this.f9257x = (ColorInfo) parcel.readParcelable(ColorInfo.class.getClassLoader());
        this.f9258y = parcel.readInt();
        this.f9259z = parcel.readInt();
        this.f9230A = parcel.readInt();
        this.f9231B = parcel.readInt();
        this.f9232C = parcel.readInt();
        this.f9233D = parcel.readString();
        this.f9234E = parcel.readInt();
        this.f9235F = null;
    }
}
