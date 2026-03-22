package com.google.android.exoplayer2.metadata;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.annotation.Nullable;
import com.google.android.exoplayer2.Format;
import java.util.Arrays;
import java.util.List;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* loaded from: classes.dex */
public final class Metadata implements Parcelable {
    public static final Parcelable.Creator<Metadata> CREATOR = new C3263a();

    /* renamed from: c */
    public final Entry[] f9273c;

    public interface Entry extends Parcelable {
        @Nullable
        /* renamed from: d */
        Format mo4051d();

        @Nullable
        /* renamed from: u */
        byte[] mo4052u();
    }

    /* renamed from: com.google.android.exoplayer2.metadata.Metadata$a */
    public static class C3263a implements Parcelable.Creator<Metadata> {
        @Override // android.os.Parcelable.Creator
        public Metadata createFromParcel(Parcel parcel) {
            return new Metadata(parcel);
        }

        @Override // android.os.Parcelable.Creator
        public Metadata[] newArray(int i2) {
            return new Metadata[i2];
        }
    }

    public Metadata(Entry... entryArr) {
        this.f9273c = entryArr;
    }

    /* renamed from: b */
    public Metadata m4053b(Entry... entryArr) {
        if (entryArr.length == 0) {
            return this;
        }
        Entry[] entryArr2 = this.f9273c;
        int i2 = C2344d0.f6035a;
        Object[] copyOf = Arrays.copyOf(entryArr2, entryArr2.length + entryArr.length);
        System.arraycopy(entryArr, 0, copyOf, entryArr2.length, entryArr.length);
        return new Metadata((Entry[]) copyOf);
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    /* renamed from: e */
    public Metadata m4054e(@Nullable Metadata metadata) {
        return metadata == null ? this : m4053b(metadata.f9273c);
    }

    public boolean equals(@Nullable Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || Metadata.class != obj.getClass()) {
            return false;
        }
        return Arrays.equals(this.f9273c, ((Metadata) obj).f9273c);
    }

    public int hashCode() {
        return Arrays.hashCode(this.f9273c);
    }

    public String toString() {
        StringBuilder m586H = C1499a.m586H("entries=");
        m586H.append(Arrays.toString(this.f9273c));
        return m586H.toString();
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int i2) {
        parcel.writeInt(this.f9273c.length);
        for (Entry entry : this.f9273c) {
            parcel.writeParcelable(entry, 0);
        }
    }

    public Metadata(List<? extends Entry> list) {
        Entry[] entryArr = new Entry[list.size()];
        this.f9273c = entryArr;
        list.toArray(entryArr);
    }

    public Metadata(Parcel parcel) {
        this.f9273c = new Entry[parcel.readInt()];
        int i2 = 0;
        while (true) {
            Entry[] entryArr = this.f9273c;
            if (i2 >= entryArr.length) {
                return;
            }
            entryArr[i2] = (Entry) parcel.readParcelable(Entry.class.getClassLoader());
            i2++;
        }
    }
}
