package android.support.v4.media.session;

import android.os.Bundle;
import android.os.Parcel;
import android.os.Parcelable;
import android.text.TextUtils;
import java.util.ArrayList;
import java.util.List;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes.dex */
public final class PlaybackStateCompat implements Parcelable {
    public static final Parcelable.Creator<PlaybackStateCompat> CREATOR = new C0031a();

    /* renamed from: c */
    public final int f80c;

    /* renamed from: e */
    public final long f81e;

    /* renamed from: f */
    public final long f82f;

    /* renamed from: g */
    public final float f83g;

    /* renamed from: h */
    public final long f84h;

    /* renamed from: i */
    public final int f85i;

    /* renamed from: j */
    public final CharSequence f86j;

    /* renamed from: k */
    public final long f87k;

    /* renamed from: l */
    public List<CustomAction> f88l;

    /* renamed from: m */
    public final long f89m;

    /* renamed from: n */
    public final Bundle f90n;

    /* renamed from: o */
    public Object f91o;

    /* renamed from: android.support.v4.media.session.PlaybackStateCompat$a */
    public static class C0031a implements Parcelable.Creator<PlaybackStateCompat> {
        @Override // android.os.Parcelable.Creator
        public PlaybackStateCompat createFromParcel(Parcel parcel) {
            return new PlaybackStateCompat(parcel);
        }

        @Override // android.os.Parcelable.Creator
        public PlaybackStateCompat[] newArray(int i2) {
            return new PlaybackStateCompat[i2];
        }
    }

    public PlaybackStateCompat(int i2, long j2, long j3, float f2, long j4, int i3, CharSequence charSequence, long j5, List<CustomAction> list, long j6, Bundle bundle) {
        this.f80c = i2;
        this.f81e = j2;
        this.f82f = j3;
        this.f83g = f2;
        this.f84h = j4;
        this.f85i = i3;
        this.f86j = charSequence;
        this.f87k = j5;
        this.f88l = new ArrayList(list);
        this.f89m = j6;
        this.f90n = bundle;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public String toString() {
        return "PlaybackState {state=" + this.f80c + ", position=" + this.f81e + ", buffered position=" + this.f82f + ", speed=" + this.f83g + ", updated=" + this.f87k + ", actions=" + this.f84h + ", error code=" + this.f85i + ", error message=" + this.f86j + ", custom actions=" + this.f88l + ", active item id=" + this.f89m + "}";
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int i2) {
        parcel.writeInt(this.f80c);
        parcel.writeLong(this.f81e);
        parcel.writeFloat(this.f83g);
        parcel.writeLong(this.f87k);
        parcel.writeLong(this.f82f);
        parcel.writeLong(this.f84h);
        TextUtils.writeToParcel(this.f86j, parcel, i2);
        parcel.writeTypedList(this.f88l);
        parcel.writeLong(this.f89m);
        parcel.writeBundle(this.f90n);
        parcel.writeInt(this.f85i);
    }

    public static final class CustomAction implements Parcelable {
        public static final Parcelable.Creator<CustomAction> CREATOR = new C0030a();

        /* renamed from: c */
        public final String f92c;

        /* renamed from: e */
        public final CharSequence f93e;

        /* renamed from: f */
        public final int f94f;

        /* renamed from: g */
        public final Bundle f95g;

        /* renamed from: h */
        public Object f96h;

        /* renamed from: android.support.v4.media.session.PlaybackStateCompat$CustomAction$a */
        public static class C0030a implements Parcelable.Creator<CustomAction> {
            @Override // android.os.Parcelable.Creator
            public CustomAction createFromParcel(Parcel parcel) {
                return new CustomAction(parcel);
            }

            @Override // android.os.Parcelable.Creator
            public CustomAction[] newArray(int i2) {
                return new CustomAction[i2];
            }
        }

        public CustomAction(String str, CharSequence charSequence, int i2, Bundle bundle) {
            this.f92c = str;
            this.f93e = charSequence;
            this.f94f = i2;
            this.f95g = bundle;
        }

        @Override // android.os.Parcelable
        public int describeContents() {
            return 0;
        }

        public String toString() {
            StringBuilder m586H = C1499a.m586H("Action:mName='");
            m586H.append((Object) this.f93e);
            m586H.append(", mIcon=");
            m586H.append(this.f94f);
            m586H.append(", mExtras=");
            m586H.append(this.f95g);
            return m586H.toString();
        }

        @Override // android.os.Parcelable
        public void writeToParcel(Parcel parcel, int i2) {
            parcel.writeString(this.f92c);
            TextUtils.writeToParcel(this.f93e, parcel, i2);
            parcel.writeInt(this.f94f);
            parcel.writeBundle(this.f95g);
        }

        public CustomAction(Parcel parcel) {
            this.f92c = parcel.readString();
            this.f93e = (CharSequence) TextUtils.CHAR_SEQUENCE_CREATOR.createFromParcel(parcel);
            this.f94f = parcel.readInt();
            this.f95g = parcel.readBundle(MediaSessionCompat.class.getClassLoader());
        }
    }

    public PlaybackStateCompat(Parcel parcel) {
        this.f80c = parcel.readInt();
        this.f81e = parcel.readLong();
        this.f83g = parcel.readFloat();
        this.f87k = parcel.readLong();
        this.f82f = parcel.readLong();
        this.f84h = parcel.readLong();
        this.f86j = (CharSequence) TextUtils.CHAR_SEQUENCE_CREATOR.createFromParcel(parcel);
        this.f88l = parcel.createTypedArrayList(CustomAction.CREATOR);
        this.f89m = parcel.readLong();
        this.f90n = parcel.readBundle(MediaSessionCompat.class.getClassLoader());
        this.f85i = parcel.readInt();
    }
}
