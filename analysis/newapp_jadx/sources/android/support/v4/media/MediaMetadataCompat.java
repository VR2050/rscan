package android.support.v4.media;

import android.os.Bundle;
import android.os.Parcel;
import android.os.Parcelable;
import android.support.v4.media.session.MediaSessionCompat;
import androidx.collection.ArrayMap;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes.dex */
public final class MediaMetadataCompat implements Parcelable {
    public static final Parcelable.Creator<MediaMetadataCompat> CREATOR;

    /* renamed from: c */
    public static final ArrayMap<String, Integer> f31c;

    /* renamed from: e */
    public final Bundle f32e;

    /* renamed from: f */
    public Object f33f;

    /* renamed from: android.support.v4.media.MediaMetadataCompat$a */
    public static class C0013a implements Parcelable.Creator<MediaMetadataCompat> {
        @Override // android.os.Parcelable.Creator
        public MediaMetadataCompat createFromParcel(Parcel parcel) {
            return new MediaMetadataCompat(parcel);
        }

        @Override // android.os.Parcelable.Creator
        public MediaMetadataCompat[] newArray(int i2) {
            return new MediaMetadataCompat[i2];
        }
    }

    /* renamed from: android.support.v4.media.MediaMetadataCompat$b */
    public static final class C0014b {

        /* renamed from: a */
        public final Bundle f34a = new Bundle();

        /* renamed from: a */
        public C0014b m11a(String str, long j2) {
            ArrayMap<String, Integer> arrayMap = MediaMetadataCompat.f31c;
            if (arrayMap.containsKey(str) && arrayMap.get(str).intValue() != 0) {
                throw new IllegalArgumentException(C1499a.m639y("The ", str, " key cannot be used to put a long"));
            }
            this.f34a.putLong(str, j2);
            return this;
        }

        /* renamed from: b */
        public C0014b m12b(String str, String str2) {
            ArrayMap<String, Integer> arrayMap = MediaMetadataCompat.f31c;
            if (arrayMap.containsKey(str) && arrayMap.get(str).intValue() != 1) {
                throw new IllegalArgumentException(C1499a.m639y("The ", str, " key cannot be used to put a String"));
            }
            this.f34a.putCharSequence(str, str2);
            return this;
        }
    }

    static {
        ArrayMap<String, Integer> arrayMap = new ArrayMap<>();
        f31c = arrayMap;
        arrayMap.put("android.media.metadata.TITLE", 1);
        arrayMap.put("android.media.metadata.ARTIST", 1);
        arrayMap.put("android.media.metadata.DURATION", 0);
        arrayMap.put("android.media.metadata.ALBUM", 1);
        arrayMap.put("android.media.metadata.AUTHOR", 1);
        arrayMap.put("android.media.metadata.WRITER", 1);
        arrayMap.put("android.media.metadata.COMPOSER", 1);
        arrayMap.put("android.media.metadata.COMPILATION", 1);
        arrayMap.put("android.media.metadata.DATE", 1);
        arrayMap.put("android.media.metadata.YEAR", 0);
        arrayMap.put("android.media.metadata.GENRE", 1);
        arrayMap.put("android.media.metadata.TRACK_NUMBER", 0);
        arrayMap.put("android.media.metadata.NUM_TRACKS", 0);
        arrayMap.put("android.media.metadata.DISC_NUMBER", 0);
        arrayMap.put("android.media.metadata.ALBUM_ARTIST", 1);
        arrayMap.put("android.media.metadata.ART", 2);
        arrayMap.put("android.media.metadata.ART_URI", 1);
        arrayMap.put("android.media.metadata.ALBUM_ART", 2);
        arrayMap.put("android.media.metadata.ALBUM_ART_URI", 1);
        arrayMap.put("android.media.metadata.USER_RATING", 3);
        arrayMap.put("android.media.metadata.RATING", 3);
        arrayMap.put("android.media.metadata.DISPLAY_TITLE", 1);
        arrayMap.put("android.media.metadata.DISPLAY_SUBTITLE", 1);
        arrayMap.put("android.media.metadata.DISPLAY_DESCRIPTION", 1);
        arrayMap.put("android.media.metadata.DISPLAY_ICON", 2);
        arrayMap.put("android.media.metadata.DISPLAY_ICON_URI", 1);
        arrayMap.put("android.media.metadata.MEDIA_ID", 1);
        arrayMap.put("android.media.metadata.BT_FOLDER_TYPE", 0);
        arrayMap.put("android.media.metadata.MEDIA_URI", 1);
        arrayMap.put("android.media.metadata.ADVERTISEMENT", 0);
        arrayMap.put("android.media.metadata.DOWNLOAD_STATUS", 0);
        CREATOR = new C0013a();
    }

    public MediaMetadataCompat(Bundle bundle) {
        Bundle bundle2 = new Bundle(bundle);
        this.f32e = bundle2;
        MediaSessionCompat.m23a(bundle2);
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int i2) {
        parcel.writeBundle(this.f32e);
    }

    public MediaMetadataCompat(Parcel parcel) {
        this.f32e = parcel.readBundle(MediaSessionCompat.class.getClassLoader());
    }
}
