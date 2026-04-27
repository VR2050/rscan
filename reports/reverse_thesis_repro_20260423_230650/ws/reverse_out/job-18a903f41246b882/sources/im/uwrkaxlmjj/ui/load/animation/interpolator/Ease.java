package im.uwrkaxlmjj.ui.load.animation.interpolator;

import android.view.animation.Interpolator;

/* JADX INFO: loaded from: classes5.dex */
public class Ease {
    public static Interpolator inOut() {
        return PathInterpolatorCompat.create(0.42f, 0.0f, 0.58f, 1.0f);
    }
}
