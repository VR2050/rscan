package com.google.android.exoplayer2.metadata.id3;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.annotation.Nullable;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* loaded from: classes.dex */
public final class UrlLinkFrame extends Id3Frame {
    public static final Parcelable.Creator<UrlLinkFrame> CREATOR = new C3279a();

    /* renamed from: e */
    @Nullable
    public final String f9337e;

    /* renamed from: f */
    public final String f9338f;

    /* renamed from: com.google.android.exoplayer2.metadata.id3.UrlLinkFrame$a */
    public static class C3279a implements Parcelable.Creator<UrlLinkFrame> {
        @Override // android.os.Parcelable.Creator
        public UrlLinkFrame createFromParcel(Parcel parcel) {
            return new UrlLinkFrame(parcel);
        }

        @Override // android.os.Parcelable.Creator
        public UrlLinkFrame[] newArray(int i2) {
            return new UrlLinkFrame[i2];
        }
    }

    public UrlLinkFrame(String str, @Nullable String str2, String str3) {
        super(str);
        this.f9337e = str2;
        this.f9338f = str3;
    }

    public boolean equals(@Nullable Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || UrlLinkFrame.class != obj.getClass()) {
            return false;
        }
        UrlLinkFrame urlLinkFrame = (UrlLinkFrame) obj;
        return this.f9324c.equals(urlLinkFrame.f9324c) && C2344d0.m2323a(this.f9337e, urlLinkFrame.f9337e) && C2344d0.m2323a(this.f9338f, urlLinkFrame.f9338f);
    }

    public int hashCode() {
        int m598T = C1499a.m598T(this.f9324c, 527, 31);
        String str = this.f9337e;
        int hashCode = (m598T + (str != null ? str.hashCode() : 0)) * 31;
        String str2 = this.f9338f;
        return hashCode + (str2 != null ? str2.hashCode() : 0);
    }

    @Override // com.google.android.exoplayer2.metadata.id3.Id3Frame
    public String toString() {
        return this.f9324c + ": url=" + this.f9338f;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int i2) {
        parcel.writeString(this.f9324c);
        parcel.writeString(this.f9337e);
        parcel.writeString(this.f9338f);
    }

    /* JADX WARN: Illegal instructions before constructor call */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public UrlLinkFrame(android.os.Parcel r3) {
        /*
            r2 = this;
            java.lang.String r0 = r3.readString()
            int r1 = p005b.p199l.p200a.p201a.p250p1.C2344d0.f6035a
            r2.<init>(r0)
            java.lang.String r0 = r3.readString()
            r2.f9337e = r0
            java.lang.String r3 = r3.readString()
            r2.f9338f = r3
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.exoplayer2.metadata.id3.UrlLinkFrame.<init>(android.os.Parcel):void");
    }
}
