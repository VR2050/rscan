package com.google.android.exoplayer2.source;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.annotation.Nullable;
import java.util.Arrays;

/* loaded from: classes.dex */
public final class TrackGroupArray implements Parcelable {

    /* renamed from: e */
    public final int f9397e;

    /* renamed from: f */
    public final TrackGroup[] f9398f;

    /* renamed from: g */
    public int f9399g;

    /* renamed from: c */
    public static final TrackGroupArray f9396c = new TrackGroupArray(new TrackGroup[0]);
    public static final Parcelable.Creator<TrackGroupArray> CREATOR = new C3293a();

    /* renamed from: com.google.android.exoplayer2.source.TrackGroupArray$a */
    public static class C3293a implements Parcelable.Creator<TrackGroupArray> {
        @Override // android.os.Parcelable.Creator
        public TrackGroupArray createFromParcel(Parcel parcel) {
            return new TrackGroupArray(parcel);
        }

        @Override // android.os.Parcelable.Creator
        public TrackGroupArray[] newArray(int i2) {
            return new TrackGroupArray[i2];
        }
    }

    public TrackGroupArray(TrackGroup... trackGroupArr) {
        this.f9398f = trackGroupArr;
        this.f9397e = trackGroupArr.length;
    }

    /* renamed from: b */
    public int m4060b(TrackGroup trackGroup) {
        for (int i2 = 0; i2 < this.f9397e; i2++) {
            if (this.f9398f[i2] == trackGroup) {
                return i2;
            }
        }
        return -1;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public boolean equals(@Nullable Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || TrackGroupArray.class != obj.getClass()) {
            return false;
        }
        TrackGroupArray trackGroupArray = (TrackGroupArray) obj;
        return this.f9397e == trackGroupArray.f9397e && Arrays.equals(this.f9398f, trackGroupArray.f9398f);
    }

    public int hashCode() {
        if (this.f9399g == 0) {
            this.f9399g = Arrays.hashCode(this.f9398f);
        }
        return this.f9399g;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int i2) {
        parcel.writeInt(this.f9397e);
        for (int i3 = 0; i3 < this.f9397e; i3++) {
            parcel.writeParcelable(this.f9398f[i3], 0);
        }
    }

    public TrackGroupArray(Parcel parcel) {
        int readInt = parcel.readInt();
        this.f9397e = readInt;
        this.f9398f = new TrackGroup[readInt];
        for (int i2 = 0; i2 < this.f9397e; i2++) {
            this.f9398f[i2] = (TrackGroup) parcel.readParcelable(TrackGroup.class.getClassLoader());
        }
    }
}
