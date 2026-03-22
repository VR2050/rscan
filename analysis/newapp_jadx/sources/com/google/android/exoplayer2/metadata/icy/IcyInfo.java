package com.google.android.exoplayer2.metadata.icy;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.annotation.Nullable;
import com.google.android.exoplayer2.Format;
import com.google.android.exoplayer2.metadata.Metadata;
import java.util.Arrays;
import java.util.Objects;
import p005b.p199l.p200a.p201a.p220h1.C2078a;

/* loaded from: classes.dex */
public final class IcyInfo implements Metadata.Entry {
    public static final Parcelable.Creator<IcyInfo> CREATOR = new C3268a();

    /* renamed from: c */
    public final byte[] f9298c;

    /* renamed from: e */
    @Nullable
    public final String f9299e;

    /* renamed from: f */
    @Nullable
    public final String f9300f;

    /* renamed from: com.google.android.exoplayer2.metadata.icy.IcyInfo$a */
    public static class C3268a implements Parcelable.Creator<IcyInfo> {
        @Override // android.os.Parcelable.Creator
        public IcyInfo createFromParcel(Parcel parcel) {
            return new IcyInfo(parcel);
        }

        @Override // android.os.Parcelable.Creator
        public IcyInfo[] newArray(int i2) {
            return new IcyInfo[i2];
        }
    }

    public IcyInfo(byte[] bArr, @Nullable String str, @Nullable String str2) {
        this.f9298c = bArr;
        this.f9299e = str;
        this.f9300f = str2;
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
        if (obj == null || IcyInfo.class != obj.getClass()) {
            return false;
        }
        return Arrays.equals(this.f9298c, ((IcyInfo) obj).f9298c);
    }

    public int hashCode() {
        return Arrays.hashCode(this.f9298c);
    }

    public String toString() {
        return String.format("ICY: title=\"%s\", url=\"%s\", rawMetadata.length=\"%s\"", this.f9299e, this.f9300f, Integer.valueOf(this.f9298c.length));
    }

    @Override // com.google.android.exoplayer2.metadata.Metadata.Entry
    /* renamed from: u */
    public /* synthetic */ byte[] mo4052u() {
        return C2078a.m1703a(this);
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int i2) {
        parcel.writeByteArray(this.f9298c);
        parcel.writeString(this.f9299e);
        parcel.writeString(this.f9300f);
    }

    public IcyInfo(Parcel parcel) {
        byte[] createByteArray = parcel.createByteArray();
        Objects.requireNonNull(createByteArray);
        this.f9298c = createByteArray;
        this.f9299e = parcel.readString();
        this.f9300f = parcel.readString();
    }
}
