package com.google.android.exoplayer2.video;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.annotation.Nullable;
import java.util.Arrays;
import net.sourceforge.pinyin4j.ChineseToPinyinResource;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* loaded from: classes.dex */
public final class ColorInfo implements Parcelable {
    public static final Parcelable.Creator<ColorInfo> CREATOR = new C3326a();

    /* renamed from: c */
    public final int f9744c;

    /* renamed from: e */
    public final int f9745e;

    /* renamed from: f */
    public final int f9746f;

    /* renamed from: g */
    @Nullable
    public final byte[] f9747g;

    /* renamed from: h */
    public int f9748h;

    /* renamed from: com.google.android.exoplayer2.video.ColorInfo$a */
    public static class C3326a implements Parcelable.Creator<ColorInfo> {
        @Override // android.os.Parcelable.Creator
        public ColorInfo createFromParcel(Parcel parcel) {
            return new ColorInfo(parcel);
        }

        @Override // android.os.Parcelable.Creator
        public ColorInfo[] newArray(int i2) {
            return new ColorInfo[i2];
        }
    }

    public ColorInfo(int i2, int i3, int i4, @Nullable byte[] bArr) {
        this.f9744c = i2;
        this.f9745e = i3;
        this.f9746f = i4;
        this.f9747g = bArr;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public boolean equals(@Nullable Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || ColorInfo.class != obj.getClass()) {
            return false;
        }
        ColorInfo colorInfo = (ColorInfo) obj;
        return this.f9744c == colorInfo.f9744c && this.f9745e == colorInfo.f9745e && this.f9746f == colorInfo.f9746f && Arrays.equals(this.f9747g, colorInfo.f9747g);
    }

    public int hashCode() {
        if (this.f9748h == 0) {
            this.f9748h = Arrays.hashCode(this.f9747g) + ((((((527 + this.f9744c) * 31) + this.f9745e) * 31) + this.f9746f) * 31);
        }
        return this.f9748h;
    }

    public String toString() {
        StringBuilder m586H = C1499a.m586H("ColorInfo(");
        m586H.append(this.f9744c);
        m586H.append(", ");
        m586H.append(this.f9745e);
        m586H.append(", ");
        m586H.append(this.f9746f);
        m586H.append(", ");
        m586H.append(this.f9747g != null);
        m586H.append(ChineseToPinyinResource.Field.RIGHT_BRACKET);
        return m586H.toString();
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int i2) {
        parcel.writeInt(this.f9744c);
        parcel.writeInt(this.f9745e);
        parcel.writeInt(this.f9746f);
        int i3 = this.f9747g != null ? 1 : 0;
        int i4 = C2344d0.f6035a;
        parcel.writeInt(i3);
        byte[] bArr = this.f9747g;
        if (bArr != null) {
            parcel.writeByteArray(bArr);
        }
    }

    public ColorInfo(Parcel parcel) {
        this.f9744c = parcel.readInt();
        this.f9745e = parcel.readInt();
        this.f9746f = parcel.readInt();
        int i2 = C2344d0.f6035a;
        this.f9747g = parcel.readInt() != 0 ? parcel.createByteArray() : null;
    }
}
