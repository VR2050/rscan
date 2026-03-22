package com.google.android.exoplayer2.metadata.flac;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.annotation.Nullable;
import com.google.android.exoplayer2.Format;
import com.google.android.exoplayer2.metadata.Metadata;
import java.util.Arrays;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p220h1.C2078a;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* loaded from: classes.dex */
public final class PictureFrame implements Metadata.Entry {
    public static final Parcelable.Creator<PictureFrame> CREATOR = new C3265a();

    /* renamed from: c */
    public final int f9282c;

    /* renamed from: e */
    public final String f9283e;

    /* renamed from: f */
    public final String f9284f;

    /* renamed from: g */
    public final int f9285g;

    /* renamed from: h */
    public final int f9286h;

    /* renamed from: i */
    public final int f9287i;

    /* renamed from: j */
    public final int f9288j;

    /* renamed from: k */
    public final byte[] f9289k;

    /* renamed from: com.google.android.exoplayer2.metadata.flac.PictureFrame$a */
    public static class C3265a implements Parcelable.Creator<PictureFrame> {
        @Override // android.os.Parcelable.Creator
        public PictureFrame createFromParcel(Parcel parcel) {
            return new PictureFrame(parcel);
        }

        @Override // android.os.Parcelable.Creator
        public PictureFrame[] newArray(int i2) {
            return new PictureFrame[i2];
        }
    }

    public PictureFrame(int i2, String str, String str2, int i3, int i4, int i5, int i6, byte[] bArr) {
        this.f9282c = i2;
        this.f9283e = str;
        this.f9284f = str2;
        this.f9285g = i3;
        this.f9286h = i4;
        this.f9287i = i5;
        this.f9288j = i6;
        this.f9289k = bArr;
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
        if (obj == null || PictureFrame.class != obj.getClass()) {
            return false;
        }
        PictureFrame pictureFrame = (PictureFrame) obj;
        return this.f9282c == pictureFrame.f9282c && this.f9283e.equals(pictureFrame.f9283e) && this.f9284f.equals(pictureFrame.f9284f) && this.f9285g == pictureFrame.f9285g && this.f9286h == pictureFrame.f9286h && this.f9287i == pictureFrame.f9287i && this.f9288j == pictureFrame.f9288j && Arrays.equals(this.f9289k, pictureFrame.f9289k);
    }

    public int hashCode() {
        return Arrays.hashCode(this.f9289k) + ((((((((C1499a.m598T(this.f9284f, C1499a.m598T(this.f9283e, (this.f9282c + 527) * 31, 31), 31) + this.f9285g) * 31) + this.f9286h) * 31) + this.f9287i) * 31) + this.f9288j) * 31);
    }

    public String toString() {
        StringBuilder m586H = C1499a.m586H("Picture: mimeType=");
        m586H.append(this.f9283e);
        m586H.append(", description=");
        m586H.append(this.f9284f);
        return m586H.toString();
    }

    @Override // com.google.android.exoplayer2.metadata.Metadata.Entry
    /* renamed from: u */
    public /* synthetic */ byte[] mo4052u() {
        return C2078a.m1703a(this);
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int i2) {
        parcel.writeInt(this.f9282c);
        parcel.writeString(this.f9283e);
        parcel.writeString(this.f9284f);
        parcel.writeInt(this.f9285g);
        parcel.writeInt(this.f9286h);
        parcel.writeInt(this.f9287i);
        parcel.writeInt(this.f9288j);
        parcel.writeByteArray(this.f9289k);
    }

    public PictureFrame(Parcel parcel) {
        this.f9282c = parcel.readInt();
        String readString = parcel.readString();
        int i2 = C2344d0.f6035a;
        this.f9283e = readString;
        this.f9284f = parcel.readString();
        this.f9285g = parcel.readInt();
        this.f9286h = parcel.readInt();
        this.f9287i = parcel.readInt();
        this.f9288j = parcel.readInt();
        this.f9289k = parcel.createByteArray();
    }
}
