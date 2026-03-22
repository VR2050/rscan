package com.google.android.exoplayer2.metadata.id3;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.annotation.Nullable;
import java.util.Arrays;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* loaded from: classes.dex */
public final class GeobFrame extends Id3Frame {
    public static final Parcelable.Creator<GeobFrame> CREATOR = new C3274a();

    /* renamed from: e */
    public final String f9320e;

    /* renamed from: f */
    public final String f9321f;

    /* renamed from: g */
    public final String f9322g;

    /* renamed from: h */
    public final byte[] f9323h;

    /* renamed from: com.google.android.exoplayer2.metadata.id3.GeobFrame$a */
    public static class C3274a implements Parcelable.Creator<GeobFrame> {
        @Override // android.os.Parcelable.Creator
        public GeobFrame createFromParcel(Parcel parcel) {
            return new GeobFrame(parcel);
        }

        @Override // android.os.Parcelable.Creator
        public GeobFrame[] newArray(int i2) {
            return new GeobFrame[i2];
        }
    }

    public GeobFrame(String str, String str2, String str3, byte[] bArr) {
        super("GEOB");
        this.f9320e = str;
        this.f9321f = str2;
        this.f9322g = str3;
        this.f9323h = bArr;
    }

    public boolean equals(@Nullable Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || GeobFrame.class != obj.getClass()) {
            return false;
        }
        GeobFrame geobFrame = (GeobFrame) obj;
        return C2344d0.m2323a(this.f9320e, geobFrame.f9320e) && C2344d0.m2323a(this.f9321f, geobFrame.f9321f) && C2344d0.m2323a(this.f9322g, geobFrame.f9322g) && Arrays.equals(this.f9323h, geobFrame.f9323h);
    }

    public int hashCode() {
        String str = this.f9320e;
        int hashCode = (527 + (str != null ? str.hashCode() : 0)) * 31;
        String str2 = this.f9321f;
        int hashCode2 = (hashCode + (str2 != null ? str2.hashCode() : 0)) * 31;
        String str3 = this.f9322g;
        return Arrays.hashCode(this.f9323h) + ((hashCode2 + (str3 != null ? str3.hashCode() : 0)) * 31);
    }

    @Override // com.google.android.exoplayer2.metadata.id3.Id3Frame
    public String toString() {
        return this.f9324c + ": mimeType=" + this.f9320e + ", filename=" + this.f9321f + ", description=" + this.f9322g;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int i2) {
        parcel.writeString(this.f9320e);
        parcel.writeString(this.f9321f);
        parcel.writeString(this.f9322g);
        parcel.writeByteArray(this.f9323h);
    }

    public GeobFrame(Parcel parcel) {
        super("GEOB");
        String readString = parcel.readString();
        int i2 = C2344d0.f6035a;
        this.f9320e = readString;
        this.f9321f = parcel.readString();
        this.f9322g = parcel.readString();
        this.f9323h = parcel.createByteArray();
    }
}
