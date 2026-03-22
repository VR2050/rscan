package com.google.android.exoplayer2.offline;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.annotation.Nullable;

/* loaded from: classes.dex */
public final class StreamKey implements Comparable<StreamKey>, Parcelable {
    public static final Parcelable.Creator<StreamKey> CREATOR = new C3290a();

    /* renamed from: c */
    public final int f9389c;

    /* renamed from: e */
    public final int f9390e;

    /* renamed from: f */
    public final int f9391f;

    /* renamed from: com.google.android.exoplayer2.offline.StreamKey$a */
    public static class C3290a implements Parcelable.Creator<StreamKey> {
        @Override // android.os.Parcelable.Creator
        public StreamKey createFromParcel(Parcel parcel) {
            return new StreamKey(parcel);
        }

        @Override // android.os.Parcelable.Creator
        public StreamKey[] newArray(int i2) {
            return new StreamKey[i2];
        }
    }

    public StreamKey(Parcel parcel) {
        this.f9389c = parcel.readInt();
        this.f9390e = parcel.readInt();
        this.f9391f = parcel.readInt();
    }

    @Override // java.lang.Comparable
    public int compareTo(StreamKey streamKey) {
        StreamKey streamKey2 = streamKey;
        int i2 = this.f9389c - streamKey2.f9389c;
        if (i2 != 0) {
            return i2;
        }
        int i3 = this.f9390e - streamKey2.f9390e;
        return i3 == 0 ? this.f9391f - streamKey2.f9391f : i3;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public boolean equals(@Nullable Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || StreamKey.class != obj.getClass()) {
            return false;
        }
        StreamKey streamKey = (StreamKey) obj;
        return this.f9389c == streamKey.f9389c && this.f9390e == streamKey.f9390e && this.f9391f == streamKey.f9391f;
    }

    public int hashCode() {
        return (((this.f9389c * 31) + this.f9390e) * 31) + this.f9391f;
    }

    public String toString() {
        return this.f9389c + "." + this.f9390e + "." + this.f9391f;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int i2) {
        parcel.writeInt(this.f9389c);
        parcel.writeInt(this.f9390e);
        parcel.writeInt(this.f9391f);
    }
}
