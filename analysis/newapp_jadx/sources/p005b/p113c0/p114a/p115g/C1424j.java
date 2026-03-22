package p005b.p113c0.p114a.p115g;

import com.yalantis.ucrop.view.CropImageView;

/* renamed from: b.c0.a.g.j */
/* loaded from: classes2.dex */
public class C1424j extends C1415a {
    public C1424j(String str) {
        super(CropImageView.DEFAULT_IMAGE_TO_CROP_BOUNDS_ANIM_DURATION, String.format("%s, %s.", "Server internal error", str));
    }

    public C1424j(Throwable th) {
        super(CropImageView.DEFAULT_IMAGE_TO_CROP_BOUNDS_ANIM_DURATION, String.format("%s.", "Server internal error"), th);
    }
}
