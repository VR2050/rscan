package com.google.android.exoplayer2.metadata.emsg;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.annotation.Nullable;
import com.google.android.exoplayer2.Format;
import com.google.android.exoplayer2.metadata.Metadata;
import java.util.Arrays;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* loaded from: classes.dex */
public final class EventMessage implements Metadata.Entry {

    /* renamed from: f */
    public final String f9276f;

    /* renamed from: g */
    public final String f9277g;

    /* renamed from: h */
    public final long f9278h;

    /* renamed from: i */
    public final long f9279i;

    /* renamed from: j */
    public final byte[] f9280j;

    /* renamed from: k */
    public int f9281k;

    /* renamed from: c */
    public static final Format f9274c = Format.m4027D(null, "application/id3", Long.MAX_VALUE);

    /* renamed from: e */
    public static final Format f9275e = Format.m4027D(null, "application/x-scte35", Long.MAX_VALUE);
    public static final Parcelable.Creator<EventMessage> CREATOR = new C3264a();

    /* renamed from: com.google.android.exoplayer2.metadata.emsg.EventMessage$a */
    public static class C3264a implements Parcelable.Creator<EventMessage> {
        @Override // android.os.Parcelable.Creator
        public EventMessage createFromParcel(Parcel parcel) {
            return new EventMessage(parcel);
        }

        @Override // android.os.Parcelable.Creator
        public EventMessage[] newArray(int i2) {
            return new EventMessage[i2];
        }
    }

    public EventMessage(String str, String str2, long j2, long j3, byte[] bArr) {
        this.f9276f = str;
        this.f9277g = str2;
        this.f9278h = j2;
        this.f9279i = j3;
        this.f9280j = bArr;
    }

    @Override // com.google.android.exoplayer2.metadata.Metadata.Entry
    @Nullable
    /* renamed from: d */
    public Format mo4051d() {
        String str = this.f9276f;
        str.hashCode();
        switch (str) {
            case "urn:scte:scte35:2014:bin":
                return f9275e;
            case "https://aomedia.org/emsg/ID3":
            case "https://developer.apple.com/streaming/emsg-id3":
                return f9274c;
            default:
                return null;
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
        if (obj == null || EventMessage.class != obj.getClass()) {
            return false;
        }
        EventMessage eventMessage = (EventMessage) obj;
        return this.f9278h == eventMessage.f9278h && this.f9279i == eventMessage.f9279i && C2344d0.m2323a(this.f9276f, eventMessage.f9276f) && C2344d0.m2323a(this.f9277g, eventMessage.f9277g) && Arrays.equals(this.f9280j, eventMessage.f9280j);
    }

    public int hashCode() {
        if (this.f9281k == 0) {
            String str = this.f9276f;
            int hashCode = (527 + (str != null ? str.hashCode() : 0)) * 31;
            String str2 = this.f9277g;
            int hashCode2 = str2 != null ? str2.hashCode() : 0;
            long j2 = this.f9278h;
            int i2 = (((hashCode + hashCode2) * 31) + ((int) (j2 ^ (j2 >>> 32)))) * 31;
            long j3 = this.f9279i;
            this.f9281k = Arrays.hashCode(this.f9280j) + ((i2 + ((int) (j3 ^ (j3 >>> 32)))) * 31);
        }
        return this.f9281k;
    }

    public String toString() {
        StringBuilder m586H = C1499a.m586H("EMSG: scheme=");
        m586H.append(this.f9276f);
        m586H.append(", id=");
        m586H.append(this.f9279i);
        m586H.append(", durationMs=");
        m586H.append(this.f9278h);
        m586H.append(", value=");
        m586H.append(this.f9277g);
        return m586H.toString();
    }

    @Override // com.google.android.exoplayer2.metadata.Metadata.Entry
    @Nullable
    /* renamed from: u */
    public byte[] mo4052u() {
        if (mo4051d() != null) {
            return this.f9280j;
        }
        return null;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int i2) {
        parcel.writeString(this.f9276f);
        parcel.writeString(this.f9277g);
        parcel.writeLong(this.f9278h);
        parcel.writeLong(this.f9279i);
        parcel.writeByteArray(this.f9280j);
    }

    public EventMessage(Parcel parcel) {
        String readString = parcel.readString();
        int i2 = C2344d0.f6035a;
        this.f9276f = readString;
        this.f9277g = parcel.readString();
        this.f9278h = parcel.readLong();
        this.f9279i = parcel.readLong();
        this.f9280j = parcel.createByteArray();
    }
}
