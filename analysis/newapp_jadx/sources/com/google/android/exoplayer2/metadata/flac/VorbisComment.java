package com.google.android.exoplayer2.metadata.flac;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.annotation.Nullable;
import com.google.android.exoplayer2.Format;
import com.google.android.exoplayer2.metadata.Metadata;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p220h1.C2078a;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* loaded from: classes.dex */
public final class VorbisComment implements Metadata.Entry {
    public static final Parcelable.Creator<VorbisComment> CREATOR = new C3266a();

    /* renamed from: c */
    public final String f9290c;

    /* renamed from: e */
    public final String f9291e;

    /* renamed from: com.google.android.exoplayer2.metadata.flac.VorbisComment$a */
    public static class C3266a implements Parcelable.Creator<VorbisComment> {
        @Override // android.os.Parcelable.Creator
        public VorbisComment createFromParcel(Parcel parcel) {
            return new VorbisComment(parcel);
        }

        @Override // android.os.Parcelable.Creator
        public VorbisComment[] newArray(int i2) {
            return new VorbisComment[i2];
        }
    }

    public VorbisComment(String str, String str2) {
        this.f9290c = str;
        this.f9291e = str2;
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
        if (obj == null || VorbisComment.class != obj.getClass()) {
            return false;
        }
        VorbisComment vorbisComment = (VorbisComment) obj;
        return this.f9290c.equals(vorbisComment.f9290c) && this.f9291e.equals(vorbisComment.f9291e);
    }

    public int hashCode() {
        return this.f9291e.hashCode() + C1499a.m598T(this.f9290c, 527, 31);
    }

    public String toString() {
        StringBuilder m586H = C1499a.m586H("VC: ");
        m586H.append(this.f9290c);
        m586H.append("=");
        m586H.append(this.f9291e);
        return m586H.toString();
    }

    @Override // com.google.android.exoplayer2.metadata.Metadata.Entry
    /* renamed from: u */
    public /* synthetic */ byte[] mo4052u() {
        return C2078a.m1703a(this);
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int i2) {
        parcel.writeString(this.f9290c);
        parcel.writeString(this.f9291e);
    }

    public VorbisComment(Parcel parcel) {
        String readString = parcel.readString();
        int i2 = C2344d0.f6035a;
        this.f9290c = readString;
        this.f9291e = parcel.readString();
    }
}
