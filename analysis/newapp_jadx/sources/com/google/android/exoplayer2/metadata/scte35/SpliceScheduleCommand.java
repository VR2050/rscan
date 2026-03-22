package com.google.android.exoplayer2.metadata.scte35;

import android.os.Parcel;
import android.os.Parcelable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/* loaded from: classes.dex */
public final class SpliceScheduleCommand extends SpliceCommand {
    public static final Parcelable.Creator<SpliceScheduleCommand> CREATOR = new C3284a();

    /* renamed from: c */
    public final List<C3286c> f9358c;

    /* renamed from: com.google.android.exoplayer2.metadata.scte35.SpliceScheduleCommand$a */
    public static class C3284a implements Parcelable.Creator<SpliceScheduleCommand> {
        @Override // android.os.Parcelable.Creator
        public SpliceScheduleCommand createFromParcel(Parcel parcel) {
            return new SpliceScheduleCommand(parcel, null);
        }

        @Override // android.os.Parcelable.Creator
        public SpliceScheduleCommand[] newArray(int i2) {
            return new SpliceScheduleCommand[i2];
        }
    }

    public SpliceScheduleCommand(List<C3286c> list) {
        this.f9358c = Collections.unmodifiableList(list);
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int i2) {
        int size = this.f9358c.size();
        parcel.writeInt(size);
        for (int i3 = 0; i3 < size; i3++) {
            C3286c c3286c = this.f9358c.get(i3);
            parcel.writeLong(c3286c.f9361a);
            parcel.writeByte(c3286c.f9362b ? (byte) 1 : (byte) 0);
            parcel.writeByte(c3286c.f9363c ? (byte) 1 : (byte) 0);
            parcel.writeByte(c3286c.f9364d ? (byte) 1 : (byte) 0);
            int size2 = c3286c.f9366f.size();
            parcel.writeInt(size2);
            for (int i4 = 0; i4 < size2; i4++) {
                C3285b c3285b = c3286c.f9366f.get(i4);
                parcel.writeInt(c3285b.f9359a);
                parcel.writeLong(c3285b.f9360b);
            }
            parcel.writeLong(c3286c.f9365e);
            parcel.writeByte(c3286c.f9367g ? (byte) 1 : (byte) 0);
            parcel.writeLong(c3286c.f9368h);
            parcel.writeInt(c3286c.f9369i);
            parcel.writeInt(c3286c.f9370j);
            parcel.writeInt(c3286c.f9371k);
        }
    }

    /* renamed from: com.google.android.exoplayer2.metadata.scte35.SpliceScheduleCommand$b */
    public static final class C3285b {

        /* renamed from: a */
        public final int f9359a;

        /* renamed from: b */
        public final long f9360b;

        public C3285b(int i2, long j2) {
            this.f9359a = i2;
            this.f9360b = j2;
        }

        public C3285b(int i2, long j2, C3284a c3284a) {
            this.f9359a = i2;
            this.f9360b = j2;
        }
    }

    public SpliceScheduleCommand(Parcel parcel, C3284a c3284a) {
        int readInt = parcel.readInt();
        ArrayList arrayList = new ArrayList(readInt);
        for (int i2 = 0; i2 < readInt; i2++) {
            arrayList.add(new C3286c(parcel));
        }
        this.f9358c = Collections.unmodifiableList(arrayList);
    }

    /* renamed from: com.google.android.exoplayer2.metadata.scte35.SpliceScheduleCommand$c */
    public static final class C3286c {

        /* renamed from: a */
        public final long f9361a;

        /* renamed from: b */
        public final boolean f9362b;

        /* renamed from: c */
        public final boolean f9363c;

        /* renamed from: d */
        public final boolean f9364d;

        /* renamed from: e */
        public final long f9365e;

        /* renamed from: f */
        public final List<C3285b> f9366f;

        /* renamed from: g */
        public final boolean f9367g;

        /* renamed from: h */
        public final long f9368h;

        /* renamed from: i */
        public final int f9369i;

        /* renamed from: j */
        public final int f9370j;

        /* renamed from: k */
        public final int f9371k;

        public C3286c(long j2, boolean z, boolean z2, boolean z3, List<C3285b> list, long j3, boolean z4, long j4, int i2, int i3, int i4) {
            this.f9361a = j2;
            this.f9362b = z;
            this.f9363c = z2;
            this.f9364d = z3;
            this.f9366f = Collections.unmodifiableList(list);
            this.f9365e = j3;
            this.f9367g = z4;
            this.f9368h = j4;
            this.f9369i = i2;
            this.f9370j = i3;
            this.f9371k = i4;
        }

        public C3286c(Parcel parcel) {
            this.f9361a = parcel.readLong();
            this.f9362b = parcel.readByte() == 1;
            this.f9363c = parcel.readByte() == 1;
            this.f9364d = parcel.readByte() == 1;
            int readInt = parcel.readInt();
            ArrayList arrayList = new ArrayList(readInt);
            for (int i2 = 0; i2 < readInt; i2++) {
                arrayList.add(new C3285b(parcel.readInt(), parcel.readLong()));
            }
            this.f9366f = Collections.unmodifiableList(arrayList);
            this.f9365e = parcel.readLong();
            this.f9367g = parcel.readByte() == 1;
            this.f9368h = parcel.readLong();
            this.f9369i = parcel.readInt();
            this.f9370j = parcel.readInt();
            this.f9371k = parcel.readInt();
        }
    }
}
