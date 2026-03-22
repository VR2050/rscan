package com.google.android.exoplayer2.trackselection;

import android.os.Parcel;
import android.os.Parcelable;
import android.text.TextUtils;
import androidx.annotation.Nullable;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* loaded from: classes.dex */
public class TrackSelectionParameters implements Parcelable {

    /* renamed from: e */
    @Nullable
    public final String f9564e;

    /* renamed from: f */
    @Nullable
    public final String f9565f;

    /* renamed from: g */
    public final int f9566g;

    /* renamed from: h */
    public final boolean f9567h;

    /* renamed from: i */
    public final int f9568i;

    /* renamed from: c */
    public static final TrackSelectionParameters f9563c = new TrackSelectionParameters(null, null, 0, false, 0);
    public static final Parcelable.Creator<TrackSelectionParameters> CREATOR = new C3312a();

    /* renamed from: com.google.android.exoplayer2.trackselection.TrackSelectionParameters$a */
    public static class C3312a implements Parcelable.Creator<TrackSelectionParameters> {
        @Override // android.os.Parcelable.Creator
        public TrackSelectionParameters createFromParcel(Parcel parcel) {
            return new TrackSelectionParameters(parcel);
        }

        @Override // android.os.Parcelable.Creator
        public TrackSelectionParameters[] newArray(int i2) {
            return new TrackSelectionParameters[i2];
        }
    }

    public TrackSelectionParameters(@Nullable String str, @Nullable String str2, int i2, boolean z, int i3) {
        this.f9564e = C2344d0.m2348z(str);
        this.f9565f = C2344d0.m2348z(str2);
        this.f9566g = i2;
        this.f9567h = z;
        this.f9568i = i3;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public boolean equals(@Nullable Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        TrackSelectionParameters trackSelectionParameters = (TrackSelectionParameters) obj;
        return TextUtils.equals(this.f9564e, trackSelectionParameters.f9564e) && TextUtils.equals(this.f9565f, trackSelectionParameters.f9565f) && this.f9566g == trackSelectionParameters.f9566g && this.f9567h == trackSelectionParameters.f9567h && this.f9568i == trackSelectionParameters.f9568i;
    }

    public int hashCode() {
        String str = this.f9564e;
        int hashCode = ((str == null ? 0 : str.hashCode()) + 31) * 31;
        String str2 = this.f9565f;
        return ((((((hashCode + (str2 != null ? str2.hashCode() : 0)) * 31) + this.f9566g) * 31) + (this.f9567h ? 1 : 0)) * 31) + this.f9568i;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int i2) {
        parcel.writeString(this.f9564e);
        parcel.writeString(this.f9565f);
        parcel.writeInt(this.f9566g);
        boolean z = this.f9567h;
        int i3 = C2344d0.f6035a;
        parcel.writeInt(z ? 1 : 0);
        parcel.writeInt(this.f9568i);
    }

    public TrackSelectionParameters(Parcel parcel) {
        this.f9564e = parcel.readString();
        this.f9565f = parcel.readString();
        this.f9566g = parcel.readInt();
        int i2 = C2344d0.f6035a;
        this.f9567h = parcel.readInt() != 0;
        this.f9568i = parcel.readInt();
    }
}
