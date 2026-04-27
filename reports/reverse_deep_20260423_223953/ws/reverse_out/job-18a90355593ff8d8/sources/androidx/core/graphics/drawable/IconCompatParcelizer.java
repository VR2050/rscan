package androidx.core.graphics.drawable;

import android.content.res.ColorStateList;
import android.os.Parcelable;

/* JADX INFO: loaded from: classes.dex */
public class IconCompatParcelizer {
    public static IconCompat read(androidx.versionedparcelable.a aVar) {
        IconCompat iconCompat = new IconCompat();
        iconCompat.f4330a = aVar.p(iconCompat.f4330a, 1);
        iconCompat.f4332c = aVar.j(iconCompat.f4332c, 2);
        iconCompat.f4333d = aVar.r(iconCompat.f4333d, 3);
        iconCompat.f4334e = aVar.p(iconCompat.f4334e, 4);
        iconCompat.f4335f = aVar.p(iconCompat.f4335f, 5);
        iconCompat.f4336g = (ColorStateList) aVar.r(iconCompat.f4336g, 6);
        iconCompat.f4338i = aVar.t(iconCompat.f4338i, 7);
        iconCompat.f4339j = aVar.t(iconCompat.f4339j, 8);
        iconCompat.f();
        return iconCompat;
    }

    public static void write(IconCompat iconCompat, androidx.versionedparcelable.a aVar) {
        aVar.x(true, true);
        iconCompat.g(aVar.f());
        int i3 = iconCompat.f4330a;
        if (-1 != i3) {
            aVar.F(i3, 1);
        }
        byte[] bArr = iconCompat.f4332c;
        if (bArr != null) {
            aVar.B(bArr, 2);
        }
        Parcelable parcelable = iconCompat.f4333d;
        if (parcelable != null) {
            aVar.H(parcelable, 3);
        }
        int i4 = iconCompat.f4334e;
        if (i4 != 0) {
            aVar.F(i4, 4);
        }
        int i5 = iconCompat.f4335f;
        if (i5 != 0) {
            aVar.F(i5, 5);
        }
        ColorStateList colorStateList = iconCompat.f4336g;
        if (colorStateList != null) {
            aVar.H(colorStateList, 6);
        }
        String str = iconCompat.f4338i;
        if (str != null) {
            aVar.J(str, 7);
        }
        String str2 = iconCompat.f4339j;
        if (str2 != null) {
            aVar.J(str2, 8);
        }
    }
}
