package com.google.android.exoplayer2.source;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.annotation.Nullable;
import com.google.android.exoplayer2.Format;
import java.util.Arrays;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* loaded from: classes.dex */
public final class TrackGroup implements Parcelable {
    public static final Parcelable.Creator<TrackGroup> CREATOR = new C3292a();

    /* renamed from: c */
    public final int f9393c;

    /* renamed from: e */
    public final Format[] f9394e;

    /* renamed from: f */
    public int f9395f;

    /* renamed from: com.google.android.exoplayer2.source.TrackGroup$a */
    public static class C3292a implements Parcelable.Creator<TrackGroup> {
        @Override // android.os.Parcelable.Creator
        public TrackGroup createFromParcel(Parcel parcel) {
            return new TrackGroup(parcel);
        }

        @Override // android.os.Parcelable.Creator
        public TrackGroup[] newArray(int i2) {
            return new TrackGroup[i2];
        }
    }

    public TrackGroup(Format... formatArr) {
        C4195m.m4771I(formatArr.length > 0);
        this.f9394e = formatArr;
        this.f9393c = formatArr.length;
    }

    /* renamed from: b */
    public int m4059b(Format format) {
        int i2 = 0;
        while (true) {
            Format[] formatArr = this.f9394e;
            if (i2 >= formatArr.length) {
                return -1;
            }
            if (format == formatArr[i2]) {
                return i2;
            }
            i2++;
        }
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public boolean equals(@Nullable Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || TrackGroup.class != obj.getClass()) {
            return false;
        }
        TrackGroup trackGroup = (TrackGroup) obj;
        return this.f9393c == trackGroup.f9393c && Arrays.equals(this.f9394e, trackGroup.f9394e);
    }

    public int hashCode() {
        if (this.f9395f == 0) {
            this.f9395f = 527 + Arrays.hashCode(this.f9394e);
        }
        return this.f9395f;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int i2) {
        parcel.writeInt(this.f9393c);
        for (int i3 = 0; i3 < this.f9393c; i3++) {
            parcel.writeParcelable(this.f9394e[i3], 0);
        }
    }

    public TrackGroup(Parcel parcel) {
        int readInt = parcel.readInt();
        this.f9393c = readInt;
        this.f9394e = new Format[readInt];
        for (int i2 = 0; i2 < this.f9393c; i2++) {
            this.f9394e[i2] = (Format) parcel.readParcelable(Format.class.getClassLoader());
        }
    }
}
