package com.google.android.exoplayer2.metadata.id3;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.annotation.Nullable;
import java.util.Arrays;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* loaded from: classes.dex */
public final class MlltFrame extends Id3Frame {
    public static final Parcelable.Creator<MlltFrame> CREATOR = new C3276a();

    /* renamed from: e */
    public final int f9328e;

    /* renamed from: f */
    public final int f9329f;

    /* renamed from: g */
    public final int f9330g;

    /* renamed from: h */
    public final int[] f9331h;

    /* renamed from: i */
    public final int[] f9332i;

    /* renamed from: com.google.android.exoplayer2.metadata.id3.MlltFrame$a */
    public static class C3276a implements Parcelable.Creator<MlltFrame> {
        @Override // android.os.Parcelable.Creator
        public MlltFrame createFromParcel(Parcel parcel) {
            return new MlltFrame(parcel);
        }

        @Override // android.os.Parcelable.Creator
        public MlltFrame[] newArray(int i2) {
            return new MlltFrame[i2];
        }
    }

    public MlltFrame(int i2, int i3, int i4, int[] iArr, int[] iArr2) {
        super("MLLT");
        this.f9328e = i2;
        this.f9329f = i3;
        this.f9330g = i4;
        this.f9331h = iArr;
        this.f9332i = iArr2;
    }

    @Override // com.google.android.exoplayer2.metadata.id3.Id3Frame, android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public boolean equals(@Nullable Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || MlltFrame.class != obj.getClass()) {
            return false;
        }
        MlltFrame mlltFrame = (MlltFrame) obj;
        return this.f9328e == mlltFrame.f9328e && this.f9329f == mlltFrame.f9329f && this.f9330g == mlltFrame.f9330g && Arrays.equals(this.f9331h, mlltFrame.f9331h) && Arrays.equals(this.f9332i, mlltFrame.f9332i);
    }

    public int hashCode() {
        return Arrays.hashCode(this.f9332i) + ((Arrays.hashCode(this.f9331h) + ((((((527 + this.f9328e) * 31) + this.f9329f) * 31) + this.f9330g) * 31)) * 31);
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int i2) {
        parcel.writeInt(this.f9328e);
        parcel.writeInt(this.f9329f);
        parcel.writeInt(this.f9330g);
        parcel.writeIntArray(this.f9331h);
        parcel.writeIntArray(this.f9332i);
    }

    public MlltFrame(Parcel parcel) {
        super("MLLT");
        this.f9328e = parcel.readInt();
        this.f9329f = parcel.readInt();
        this.f9330g = parcel.readInt();
        int[] createIntArray = parcel.createIntArray();
        int i2 = C2344d0.f6035a;
        this.f9331h = createIntArray;
        this.f9332i = parcel.createIntArray();
    }
}
