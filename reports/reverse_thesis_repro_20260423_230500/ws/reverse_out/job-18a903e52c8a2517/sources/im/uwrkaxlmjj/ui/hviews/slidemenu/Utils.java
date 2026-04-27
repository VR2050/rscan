package im.uwrkaxlmjj.ui.hviews.slidemenu;

import android.graphics.drawable.Drawable;
import android.view.View;
import android.widget.LinearLayout;
import androidx.core.graphics.drawable.DrawableCompat;

/* JADX INFO: loaded from: classes5.dex */
class Utils {
    Utils() {
    }

    static float getViewWeight(View view) {
        LinearLayout.LayoutParams lp = (LinearLayout.LayoutParams) view.getLayoutParams();
        return lp.weight;
    }

    static void setViewWeight(View view, float weight) {
        LinearLayout.LayoutParams lp = (LinearLayout.LayoutParams) view.getLayoutParams();
        lp.weight = weight;
        view.setLayoutParams(lp);
    }

    static void setViewWidth(View view, int width) {
        view.getLayoutParams().width = width;
        view.requestLayout();
    }

    static void setViewHeight(View view, int height) {
        view.getLayoutParams().height = height;
        view.requestLayout();
    }

    static Drawable setTint(Drawable drawable, int color) {
        Drawable drawable2 = DrawableCompat.wrap(drawable);
        DrawableCompat.setTint(drawable2, color);
        return drawable2.mutate();
    }
}
