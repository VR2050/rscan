package com.google.android.exoplayer2.metadata.icy;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.annotation.Nullable;
import com.google.android.exoplayer2.Format;
import com.google.android.exoplayer2.metadata.Metadata;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p220h1.C2078a;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* loaded from: classes.dex */
public final class IcyHeaders implements Metadata.Entry {
    public static final Parcelable.Creator<IcyHeaders> CREATOR = new C3267a();

    /* renamed from: c */
    public final int f9292c;

    /* renamed from: e */
    @Nullable
    public final String f9293e;

    /* renamed from: f */
    @Nullable
    public final String f9294f;

    /* renamed from: g */
    @Nullable
    public final String f9295g;

    /* renamed from: h */
    public final boolean f9296h;

    /* renamed from: i */
    public final int f9297i;

    /* renamed from: com.google.android.exoplayer2.metadata.icy.IcyHeaders$a */
    public static class C3267a implements Parcelable.Creator<IcyHeaders> {
        @Override // android.os.Parcelable.Creator
        public IcyHeaders createFromParcel(Parcel parcel) {
            return new IcyHeaders(parcel);
        }

        @Override // android.os.Parcelable.Creator
        public IcyHeaders[] newArray(int i2) {
            return new IcyHeaders[i2];
        }
    }

    public IcyHeaders(int i2, @Nullable String str, @Nullable String str2, @Nullable String str3, boolean z, int i3) {
        C4195m.m4765F(i3 == -1 || i3 > 0);
        this.f9292c = i2;
        this.f9293e = str;
        this.f9294f = str2;
        this.f9295g = str3;
        this.f9296h = z;
        this.f9297i = i3;
    }

    /* JADX WARN: Removed duplicated region for block: B:12:0x002e  */
    /* JADX WARN: Removed duplicated region for block: B:15:0x0042  */
    /* JADX WARN: Removed duplicated region for block: B:18:0x0056  */
    /* JADX WARN: Removed duplicated region for block: B:21:0x006a  */
    /* JADX WARN: Removed duplicated region for block: B:24:0x0084  */
    /* JADX WARN: Removed duplicated region for block: B:31:0x0099  */
    /* JADX WARN: Removed duplicated region for block: B:34:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:39:0x0079  */
    /* JADX WARN: Removed duplicated region for block: B:40:0x005f  */
    /* JADX WARN: Removed duplicated region for block: B:41:0x004b  */
    /* JADX WARN: Removed duplicated region for block: B:42:0x0037  */
    @androidx.annotation.Nullable
    /* renamed from: b */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static com.google.android.exoplayer2.metadata.icy.IcyHeaders m4055b(java.util.Map<java.lang.String, java.util.List<java.lang.String>> r12) {
        /*
            java.lang.String r0 = "icy-br"
            java.lang.Object r0 = r12.get(r0)
            java.util.List r0 = (java.util.List) r0
            r1 = -1
            r2 = 1
            r3 = 0
            if (r0 == 0) goto L21
            java.lang.Object r0 = r0.get(r3)
            java.lang.String r0 = (java.lang.String) r0
            int r0 = java.lang.Integer.parseInt(r0)     // Catch: java.lang.NumberFormatException -> L21
            int r0 = r0 * 1000
            if (r0 <= 0) goto L1d
            r4 = 1
            goto L1f
        L1d:
            r0 = -1
            r4 = 0
        L1f:
            r6 = r0
            goto L23
        L21:
            r4 = 0
            r6 = -1
        L23:
            java.lang.String r0 = "icy-genre"
            java.lang.Object r0 = r12.get(r0)
            java.util.List r0 = (java.util.List) r0
            r5 = 0
            if (r0 == 0) goto L37
            java.lang.Object r0 = r0.get(r3)
            java.lang.String r0 = (java.lang.String) r0
            r7 = r0
            r4 = 1
            goto L38
        L37:
            r7 = r5
        L38:
            java.lang.String r0 = "icy-name"
            java.lang.Object r0 = r12.get(r0)
            java.util.List r0 = (java.util.List) r0
            if (r0 == 0) goto L4b
            java.lang.Object r0 = r0.get(r3)
            java.lang.String r0 = (java.lang.String) r0
            r8 = r0
            r4 = 1
            goto L4c
        L4b:
            r8 = r5
        L4c:
            java.lang.String r0 = "icy-url"
            java.lang.Object r0 = r12.get(r0)
            java.util.List r0 = (java.util.List) r0
            if (r0 == 0) goto L5f
            java.lang.Object r0 = r0.get(r3)
            java.lang.String r0 = (java.lang.String) r0
            r9 = r0
            r4 = 1
            goto L60
        L5f:
            r9 = r5
        L60:
            java.lang.String r0 = "icy-pub"
            java.lang.Object r0 = r12.get(r0)
            java.util.List r0 = (java.util.List) r0
            if (r0 == 0) goto L79
            java.lang.Object r0 = r0.get(r3)
            java.lang.String r0 = (java.lang.String) r0
            java.lang.String r4 = "1"
            boolean r0 = r0.equals(r4)
            r10 = r0
            r4 = 1
            goto L7a
        L79:
            r10 = 0
        L7a:
            java.lang.String r0 = "icy-metaint"
            java.lang.Object r12 = r12.get(r0)
            java.util.List r12 = (java.util.List) r12
            if (r12 == 0) goto L96
            java.lang.Object r12 = r12.get(r3)
            java.lang.String r12 = (java.lang.String) r12
            int r12 = java.lang.Integer.parseInt(r12)     // Catch: java.lang.NumberFormatException -> L96
            if (r12 <= 0) goto L92
            r1 = r12
            goto L93
        L92:
            r2 = r4
        L93:
            r11 = r1
            r4 = r2
            goto L97
        L96:
            r11 = -1
        L97:
            if (r4 == 0) goto L9f
            com.google.android.exoplayer2.metadata.icy.IcyHeaders r12 = new com.google.android.exoplayer2.metadata.icy.IcyHeaders
            r5 = r12
            r5.<init>(r6, r7, r8, r9, r10, r11)
        L9f:
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.exoplayer2.metadata.icy.IcyHeaders.m4055b(java.util.Map):com.google.android.exoplayer2.metadata.icy.IcyHeaders");
    }

    @Override // com.google.android.exoplayer2.metadata.Metadata.Entry
    /* renamed from: d */
    public /* synthetic */ Format mo4051d() {
        return C2078a.m1704b(this);
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public boolean equals(@Nullable Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || IcyHeaders.class != obj.getClass()) {
            return false;
        }
        IcyHeaders icyHeaders = (IcyHeaders) obj;
        return this.f9292c == icyHeaders.f9292c && C2344d0.m2323a(this.f9293e, icyHeaders.f9293e) && C2344d0.m2323a(this.f9294f, icyHeaders.f9294f) && C2344d0.m2323a(this.f9295g, icyHeaders.f9295g) && this.f9296h == icyHeaders.f9296h && this.f9297i == icyHeaders.f9297i;
    }

    public int hashCode() {
        int i2 = (527 + this.f9292c) * 31;
        String str = this.f9293e;
        int hashCode = (i2 + (str != null ? str.hashCode() : 0)) * 31;
        String str2 = this.f9294f;
        int hashCode2 = (hashCode + (str2 != null ? str2.hashCode() : 0)) * 31;
        String str3 = this.f9295g;
        return ((((hashCode2 + (str3 != null ? str3.hashCode() : 0)) * 31) + (this.f9296h ? 1 : 0)) * 31) + this.f9297i;
    }

    public String toString() {
        StringBuilder m586H = C1499a.m586H("IcyHeaders: name=\"");
        m586H.append(this.f9294f);
        m586H.append("\", genre=\"");
        m586H.append(this.f9293e);
        m586H.append("\", bitrate=");
        m586H.append(this.f9292c);
        m586H.append(", metadataInterval=");
        m586H.append(this.f9297i);
        return m586H.toString();
    }

    @Override // com.google.android.exoplayer2.metadata.Metadata.Entry
    /* renamed from: u */
    public /* synthetic */ byte[] mo4052u() {
        return C2078a.m1703a(this);
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int i2) {
        parcel.writeInt(this.f9292c);
        parcel.writeString(this.f9293e);
        parcel.writeString(this.f9294f);
        parcel.writeString(this.f9295g);
        boolean z = this.f9296h;
        int i3 = C2344d0.f6035a;
        parcel.writeInt(z ? 1 : 0);
        parcel.writeInt(this.f9297i);
    }

    public IcyHeaders(Parcel parcel) {
        this.f9292c = parcel.readInt();
        this.f9293e = parcel.readString();
        this.f9294f = parcel.readString();
        this.f9295g = parcel.readString();
        int i2 = C2344d0.f6035a;
        this.f9296h = parcel.readInt() != 0;
        this.f9297i = parcel.readInt();
    }
}
