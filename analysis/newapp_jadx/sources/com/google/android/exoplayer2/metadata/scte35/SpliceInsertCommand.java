package com.google.android.exoplayer2.metadata.scte35;

import android.os.Parcel;
import android.os.Parcelable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/* loaded from: classes.dex */
public final class SpliceInsertCommand extends SpliceCommand {
    public static final Parcelable.Creator<SpliceInsertCommand> CREATOR = new C3281a();

    /* renamed from: c */
    public final long f9342c;

    /* renamed from: e */
    public final boolean f9343e;

    /* renamed from: f */
    public final boolean f9344f;

    /* renamed from: g */
    public final boolean f9345g;

    /* renamed from: h */
    public final boolean f9346h;

    /* renamed from: i */
    public final long f9347i;

    /* renamed from: j */
    public final long f9348j;

    /* renamed from: k */
    public final List<C3282b> f9349k;

    /* renamed from: l */
    public final boolean f9350l;

    /* renamed from: m */
    public final long f9351m;

    /* renamed from: n */
    public final int f9352n;

    /* renamed from: o */
    public final int f9353o;

    /* renamed from: p */
    public final int f9354p;

    /* renamed from: com.google.android.exoplayer2.metadata.scte35.SpliceInsertCommand$a */
    public static class C3281a implements Parcelable.Creator<SpliceInsertCommand> {
        @Override // android.os.Parcelable.Creator
        public SpliceInsertCommand createFromParcel(Parcel parcel) {
            return new SpliceInsertCommand(parcel, null);
        }

        @Override // android.os.Parcelable.Creator
        public SpliceInsertCommand[] newArray(int i2) {
            return new SpliceInsertCommand[i2];
        }
    }

    public SpliceInsertCommand(long j2, boolean z, boolean z2, boolean z3, boolean z4, long j3, long j4, List<C3282b> list, boolean z5, long j5, int i2, int i3, int i4) {
        this.f9342c = j2;
        this.f9343e = z;
        this.f9344f = z2;
        this.f9345g = z3;
        this.f9346h = z4;
        this.f9347i = j3;
        this.f9348j = j4;
        this.f9349k = Collections.unmodifiableList(list);
        this.f9350l = z5;
        this.f9351m = j5;
        this.f9352n = i2;
        this.f9353o = i3;
        this.f9354p = i4;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int i2) {
        parcel.writeLong(this.f9342c);
        parcel.writeByte(this.f9343e ? (byte) 1 : (byte) 0);
        parcel.writeByte(this.f9344f ? (byte) 1 : (byte) 0);
        parcel.writeByte(this.f9345g ? (byte) 1 : (byte) 0);
        parcel.writeByte(this.f9346h ? (byte) 1 : (byte) 0);
        parcel.writeLong(this.f9347i);
        parcel.writeLong(this.f9348j);
        int size = this.f9349k.size();
        parcel.writeInt(size);
        for (int i3 = 0; i3 < size; i3++) {
            C3282b c3282b = this.f9349k.get(i3);
            parcel.writeInt(c3282b.f9355a);
            parcel.writeLong(c3282b.f9356b);
            parcel.writeLong(c3282b.f9357c);
        }
        parcel.writeByte(this.f9350l ? (byte) 1 : (byte) 0);
        parcel.writeLong(this.f9351m);
        parcel.writeInt(this.f9352n);
        parcel.writeInt(this.f9353o);
        parcel.writeInt(this.f9354p);
    }

    /* renamed from: com.google.android.exoplayer2.metadata.scte35.SpliceInsertCommand$b */
    public static final class C3282b {

        /* renamed from: a */
        public final int f9355a;

        /* renamed from: b */
        public final long f9356b;

        /* renamed from: c */
        public final long f9357c;

        public C3282b(int i2, long j2, long j3) {
            this.f9355a = i2;
            this.f9356b = j2;
            this.f9357c = j3;
        }

        public C3282b(int i2, long j2, long j3, C3281a c3281a) {
            this.f9355a = i2;
            this.f9356b = j2;
            this.f9357c = j3;
        }
    }

    public SpliceInsertCommand(Parcel parcel, C3281a c3281a) {
        this.f9342c = parcel.readLong();
        this.f9343e = parcel.readByte() == 1;
        this.f9344f = parcel.readByte() == 1;
        this.f9345g = parcel.readByte() == 1;
        this.f9346h = parcel.readByte() == 1;
        this.f9347i = parcel.readLong();
        this.f9348j = parcel.readLong();
        int readInt = parcel.readInt();
        ArrayList arrayList = new ArrayList(readInt);
        for (int i2 = 0; i2 < readInt; i2++) {
            arrayList.add(new C3282b(parcel.readInt(), parcel.readLong(), parcel.readLong()));
        }
        this.f9349k = Collections.unmodifiableList(arrayList);
        this.f9350l = parcel.readByte() == 1;
        this.f9351m = parcel.readLong();
        this.f9352n = parcel.readInt();
        this.f9353o = parcel.readInt();
        this.f9354p = parcel.readInt();
    }
}
