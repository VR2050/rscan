package com.google.android.exoplayer2.metadata.id3;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.annotation.Nullable;
import java.util.Arrays;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* loaded from: classes.dex */
public final class ChapterTocFrame extends Id3Frame {
    public static final Parcelable.Creator<ChapterTocFrame> CREATOR = new C3272a();

    /* renamed from: e */
    public final String f9312e;

    /* renamed from: f */
    public final boolean f9313f;

    /* renamed from: g */
    public final boolean f9314g;

    /* renamed from: h */
    public final String[] f9315h;

    /* renamed from: i */
    public final Id3Frame[] f9316i;

    /* renamed from: com.google.android.exoplayer2.metadata.id3.ChapterTocFrame$a */
    public static class C3272a implements Parcelable.Creator<ChapterTocFrame> {
        @Override // android.os.Parcelable.Creator
        public ChapterTocFrame createFromParcel(Parcel parcel) {
            return new ChapterTocFrame(parcel);
        }

        @Override // android.os.Parcelable.Creator
        public ChapterTocFrame[] newArray(int i2) {
            return new ChapterTocFrame[i2];
        }
    }

    public ChapterTocFrame(String str, boolean z, boolean z2, String[] strArr, Id3Frame[] id3FrameArr) {
        super("CTOC");
        this.f9312e = str;
        this.f9313f = z;
        this.f9314g = z2;
        this.f9315h = strArr;
        this.f9316i = id3FrameArr;
    }

    public boolean equals(@Nullable Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || ChapterTocFrame.class != obj.getClass()) {
            return false;
        }
        ChapterTocFrame chapterTocFrame = (ChapterTocFrame) obj;
        return this.f9313f == chapterTocFrame.f9313f && this.f9314g == chapterTocFrame.f9314g && C2344d0.m2323a(this.f9312e, chapterTocFrame.f9312e) && Arrays.equals(this.f9315h, chapterTocFrame.f9315h) && Arrays.equals(this.f9316i, chapterTocFrame.f9316i);
    }

    public int hashCode() {
        int i2 = (((527 + (this.f9313f ? 1 : 0)) * 31) + (this.f9314g ? 1 : 0)) * 31;
        String str = this.f9312e;
        return i2 + (str != null ? str.hashCode() : 0);
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int i2) {
        parcel.writeString(this.f9312e);
        parcel.writeByte(this.f9313f ? (byte) 1 : (byte) 0);
        parcel.writeByte(this.f9314g ? (byte) 1 : (byte) 0);
        parcel.writeStringArray(this.f9315h);
        parcel.writeInt(this.f9316i.length);
        for (Id3Frame id3Frame : this.f9316i) {
            parcel.writeParcelable(id3Frame, 0);
        }
    }

    public ChapterTocFrame(Parcel parcel) {
        super("CTOC");
        String readString = parcel.readString();
        int i2 = C2344d0.f6035a;
        this.f9312e = readString;
        this.f9313f = parcel.readByte() != 0;
        this.f9314g = parcel.readByte() != 0;
        this.f9315h = parcel.createStringArray();
        int readInt = parcel.readInt();
        this.f9316i = new Id3Frame[readInt];
        for (int i3 = 0; i3 < readInt; i3++) {
            this.f9316i[i3] = (Id3Frame) parcel.readParcelable(Id3Frame.class.getClassLoader());
        }
    }
}
