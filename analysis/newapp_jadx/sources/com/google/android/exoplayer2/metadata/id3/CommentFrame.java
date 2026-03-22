package com.google.android.exoplayer2.metadata.id3;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.annotation.Nullable;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* loaded from: classes.dex */
public final class CommentFrame extends Id3Frame {
    public static final Parcelable.Creator<CommentFrame> CREATOR = new C3273a();

    /* renamed from: e */
    public final String f9317e;

    /* renamed from: f */
    public final String f9318f;

    /* renamed from: g */
    public final String f9319g;

    /* renamed from: com.google.android.exoplayer2.metadata.id3.CommentFrame$a */
    public static class C3273a implements Parcelable.Creator<CommentFrame> {
        @Override // android.os.Parcelable.Creator
        public CommentFrame createFromParcel(Parcel parcel) {
            return new CommentFrame(parcel);
        }

        @Override // android.os.Parcelable.Creator
        public CommentFrame[] newArray(int i2) {
            return new CommentFrame[i2];
        }
    }

    public CommentFrame(String str, String str2, String str3) {
        super("COMM");
        this.f9317e = str;
        this.f9318f = str2;
        this.f9319g = str3;
    }

    public boolean equals(@Nullable Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || CommentFrame.class != obj.getClass()) {
            return false;
        }
        CommentFrame commentFrame = (CommentFrame) obj;
        return C2344d0.m2323a(this.f9318f, commentFrame.f9318f) && C2344d0.m2323a(this.f9317e, commentFrame.f9317e) && C2344d0.m2323a(this.f9319g, commentFrame.f9319g);
    }

    public int hashCode() {
        String str = this.f9317e;
        int hashCode = (527 + (str != null ? str.hashCode() : 0)) * 31;
        String str2 = this.f9318f;
        int hashCode2 = (hashCode + (str2 != null ? str2.hashCode() : 0)) * 31;
        String str3 = this.f9319g;
        return hashCode2 + (str3 != null ? str3.hashCode() : 0);
    }

    @Override // com.google.android.exoplayer2.metadata.id3.Id3Frame
    public String toString() {
        return this.f9324c + ": language=" + this.f9317e + ", description=" + this.f9318f;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int i2) {
        parcel.writeString(this.f9324c);
        parcel.writeString(this.f9317e);
        parcel.writeString(this.f9319g);
    }

    public CommentFrame(Parcel parcel) {
        super("COMM");
        String readString = parcel.readString();
        int i2 = C2344d0.f6035a;
        this.f9317e = readString;
        this.f9318f = parcel.readString();
        this.f9319g = parcel.readString();
    }
}
