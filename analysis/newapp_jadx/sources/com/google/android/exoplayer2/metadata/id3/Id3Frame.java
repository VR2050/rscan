package com.google.android.exoplayer2.metadata.id3;

import com.google.android.exoplayer2.Format;
import com.google.android.exoplayer2.metadata.Metadata;
import p005b.p199l.p200a.p201a.p220h1.C2078a;

/* loaded from: classes.dex */
public abstract class Id3Frame implements Metadata.Entry {

    /* renamed from: c */
    public final String f9324c;

    public Id3Frame(String str) {
        this.f9324c = str;
    }

    @Override // com.google.android.exoplayer2.metadata.Metadata.Entry
    /* renamed from: d */
    public /* synthetic */ Format mo4051d() {
        return C2078a.m1704b(this);
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public String toString() {
        return this.f9324c;
    }

    @Override // com.google.android.exoplayer2.metadata.Metadata.Entry
    /* renamed from: u */
    public /* synthetic */ byte[] mo4052u() {
        return C2078a.m1703a(this);
    }
}
