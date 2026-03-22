package com.google.android.exoplayer2.metadata.id3;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.annotation.Nullable;
import java.util.Arrays;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* loaded from: classes.dex */
public final class ChapterFrame extends Id3Frame {
    public static final Parcelable.Creator<ChapterFrame> CREATOR = new C3271a();

    /* renamed from: e */
    public final String f9306e;

    /* renamed from: f */
    public final int f9307f;

    /* renamed from: g */
    public final int f9308g;

    /* renamed from: h */
    public final long f9309h;

    /* renamed from: i */
    public final long f9310i;

    /* renamed from: j */
    public final Id3Frame[] f9311j;

    /* renamed from: com.google.android.exoplayer2.metadata.id3.ChapterFrame$a */
    public static class C3271a implements Parcelable.Creator<ChapterFrame> {
        @Override // android.os.Parcelable.Creator
        public ChapterFrame createFromParcel(Parcel parcel) {
            return new ChapterFrame(parcel);
        }

        @Override // android.os.Parcelable.Creator
        public ChapterFrame[] newArray(int i2) {
            return new ChapterFrame[i2];
        }
    }

    public ChapterFrame(String str, int i2, int i3, long j2, long j3, Id3Frame[] id3FrameArr) {
        super("CHAP");
        this.f9306e = str;
        this.f9307f = i2;
        this.f9308g = i3;
        this.f9309h = j2;
        this.f9310i = j3;
        this.f9311j = id3FrameArr;
    }

    @Override // com.google.android.exoplayer2.metadata.id3.Id3Frame, android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public boolean equals(@Nullable Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || ChapterFrame.class != obj.getClass()) {
            return false;
        }
        ChapterFrame chapterFrame = (ChapterFrame) obj;
        return this.f9307f == chapterFrame.f9307f && this.f9308g == chapterFrame.f9308g && this.f9309h == chapterFrame.f9309h && this.f9310i == chapterFrame.f9310i && C2344d0.m2323a(this.f9306e, chapterFrame.f9306e) && Arrays.equals(this.f9311j, chapterFrame.f9311j);
    }

    public int hashCode() {
        int i2 = (((((((527 + this.f9307f) * 31) + this.f9308g) * 31) + ((int) this.f9309h)) * 31) + ((int) this.f9310i)) * 31;
        String str = this.f9306e;
        return i2 + (str != null ? str.hashCode() : 0);
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int i2) {
        parcel.writeString(this.f9306e);
        parcel.writeInt(this.f9307f);
        parcel.writeInt(this.f9308g);
        parcel.writeLong(this.f9309h);
        parcel.writeLong(this.f9310i);
        parcel.writeInt(this.f9311j.length);
        for (Id3Frame id3Frame : this.f9311j) {
            parcel.writeParcelable(id3Frame, 0);
        }
    }

    public ChapterFrame(Parcel parcel) {
        super("CHAP");
        String readString = parcel.readString();
        int i2 = C2344d0.f6035a;
        this.f9306e = readString;
        this.f9307f = parcel.readInt();
        this.f9308g = parcel.readInt();
        this.f9309h = parcel.readLong();
        this.f9310i = parcel.readLong();
        int readInt = parcel.readInt();
        this.f9311j = new Id3Frame[readInt];
        for (int i3 = 0; i3 < readInt; i3++) {
            this.f9311j[i3] = (Id3Frame) parcel.readParcelable(Id3Frame.class.getClassLoader());
        }
    }
}
