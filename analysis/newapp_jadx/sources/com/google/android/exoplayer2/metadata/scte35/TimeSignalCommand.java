package com.google.android.exoplayer2.metadata.scte35;

import android.os.Parcel;
import android.os.Parcelable;
import p005b.p199l.p200a.p201a.p250p1.C2360t;

/* loaded from: classes.dex */
public final class TimeSignalCommand extends SpliceCommand {
    public static final Parcelable.Creator<TimeSignalCommand> CREATOR = new C3287a();

    /* renamed from: c */
    public final long f9372c;

    /* renamed from: e */
    public final long f9373e;

    /* renamed from: com.google.android.exoplayer2.metadata.scte35.TimeSignalCommand$a */
    public static class C3287a implements Parcelable.Creator<TimeSignalCommand> {
        @Override // android.os.Parcelable.Creator
        public TimeSignalCommand createFromParcel(Parcel parcel) {
            return new TimeSignalCommand(parcel.readLong(), parcel.readLong(), null);
        }

        @Override // android.os.Parcelable.Creator
        public TimeSignalCommand[] newArray(int i2) {
            return new TimeSignalCommand[i2];
        }
    }

    public TimeSignalCommand(long j2, long j3) {
        this.f9372c = j2;
        this.f9373e = j3;
    }

    /* renamed from: b */
    public static long m4056b(C2360t c2360t, long j2) {
        long m2585q = c2360t.m2585q();
        if ((128 & m2585q) != 0) {
            return 8589934591L & ((((m2585q & 1) << 32) | c2360t.m2586r()) + j2);
        }
        return -9223372036854775807L;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int i2) {
        parcel.writeLong(this.f9372c);
        parcel.writeLong(this.f9373e);
    }

    public TimeSignalCommand(long j2, long j3, C3287a c3287a) {
        this.f9372c = j2;
        this.f9373e = j3;
    }
}
