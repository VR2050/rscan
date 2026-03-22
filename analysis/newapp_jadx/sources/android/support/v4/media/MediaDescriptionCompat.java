package android.support.v4.media;

import android.graphics.Bitmap;
import android.media.MediaDescription;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Parcel;
import android.os.Parcelable;

/* loaded from: classes.dex */
public final class MediaDescriptionCompat implements Parcelable {
    public static final Parcelable.Creator<MediaDescriptionCompat> CREATOR = new C0012a();

    /* renamed from: c */
    public final String f22c;

    /* renamed from: e */
    public final CharSequence f23e;

    /* renamed from: f */
    public final CharSequence f24f;

    /* renamed from: g */
    public final CharSequence f25g;

    /* renamed from: h */
    public final Bitmap f26h;

    /* renamed from: i */
    public final Uri f27i;

    /* renamed from: j */
    public final Bundle f28j;

    /* renamed from: k */
    public final Uri f29k;

    /* renamed from: l */
    public Object f30l;

    /* renamed from: android.support.v4.media.MediaDescriptionCompat$a */
    public static class C0012a implements Parcelable.Creator<MediaDescriptionCompat> {
        @Override // android.os.Parcelable.Creator
        public MediaDescriptionCompat createFromParcel(Parcel parcel) {
            return MediaDescriptionCompat.m10b(MediaDescription.CREATOR.createFromParcel(parcel));
        }

        @Override // android.os.Parcelable.Creator
        public MediaDescriptionCompat[] newArray(int i2) {
            return new MediaDescriptionCompat[i2];
        }
    }

    public MediaDescriptionCompat(String str, CharSequence charSequence, CharSequence charSequence2, CharSequence charSequence3, Bitmap bitmap, Uri uri, Bundle bundle, Uri uri2) {
        this.f22c = str;
        this.f23e = charSequence;
        this.f24f = charSequence2;
        this.f25g = charSequence3;
        this.f26h = bitmap;
        this.f27i = uri;
        this.f28j = bundle;
        this.f29k = uri2;
    }

    /* JADX WARN: Removed duplicated region for block: B:13:0x0050  */
    /* renamed from: b */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static android.support.v4.media.MediaDescriptionCompat m10b(java.lang.Object r15) {
        /*
            r0 = 0
            if (r15 == 0) goto L61
            int r1 = android.os.Build.VERSION.SDK_INT
            r2 = r15
            android.media.MediaDescription r2 = (android.media.MediaDescription) r2
            java.lang.String r4 = r2.getMediaId()
            java.lang.CharSequence r5 = r2.getTitle()
            java.lang.CharSequence r6 = r2.getSubtitle()
            java.lang.CharSequence r7 = r2.getDescription()
            android.graphics.Bitmap r8 = r2.getIconBitmap()
            android.net.Uri r9 = r2.getIconUri()
            android.os.Bundle r3 = r2.getExtras()
            java.lang.String r10 = "android.support.v4.media.description.MEDIA_URI"
            if (r3 == 0) goto L32
            android.support.v4.media.session.MediaSessionCompat.m23a(r3)
            android.os.Parcelable r11 = r3.getParcelable(r10)
            android.net.Uri r11 = (android.net.Uri) r11
            goto L33
        L32:
            r11 = r0
        L33:
            if (r11 == 0) goto L4c
            java.lang.String r12 = "android.support.v4.media.description.NULL_BUNDLE_FLAG"
            boolean r13 = r3.containsKey(r12)
            if (r13 == 0) goto L46
            int r13 = r3.size()
            r14 = 2
            if (r13 != r14) goto L46
            r10 = r0
            goto L4d
        L46:
            r3.remove(r10)
            r3.remove(r12)
        L4c:
            r10 = r3
        L4d:
            if (r11 == 0) goto L50
            goto L59
        L50:
            r3 = 23
            if (r1 < r3) goto L58
            android.net.Uri r0 = r2.getMediaUri()
        L58:
            r11 = r0
        L59:
            android.support.v4.media.MediaDescriptionCompat r0 = new android.support.v4.media.MediaDescriptionCompat
            r3 = r0
            r3.<init>(r4, r5, r6, r7, r8, r9, r10, r11)
            r0.f30l = r15
        L61:
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: android.support.v4.media.MediaDescriptionCompat.m10b(java.lang.Object):android.support.v4.media.MediaDescriptionCompat");
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public String toString() {
        return ((Object) this.f23e) + ", " + ((Object) this.f24f) + ", " + ((Object) this.f25g);
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int i2) {
        int i3 = Build.VERSION.SDK_INT;
        Object obj = this.f30l;
        if (obj == null) {
            MediaDescription.Builder builder = new MediaDescription.Builder();
            builder.setMediaId(this.f22c);
            builder.setTitle(this.f23e);
            builder.setSubtitle(this.f24f);
            builder.setDescription(this.f25g);
            builder.setIconBitmap(this.f26h);
            builder.setIconUri(this.f27i);
            Bundle bundle = this.f28j;
            if (i3 < 23 && this.f29k != null) {
                if (bundle == null) {
                    bundle = new Bundle();
                    bundle.putBoolean("android.support.v4.media.description.NULL_BUNDLE_FLAG", true);
                }
                bundle.putParcelable("android.support.v4.media.description.MEDIA_URI", this.f29k);
            }
            builder.setExtras(bundle);
            if (i3 >= 23) {
                builder.setMediaUri(this.f29k);
            }
            obj = builder.build();
            this.f30l = obj;
        }
        ((MediaDescription) obj).writeToParcel(parcel, i2);
    }
}
