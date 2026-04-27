package im.uwrkaxlmjj.ui.hviews.swipelist;

import android.view.View;
import androidx.core.view.ViewCompat;

/* JADX INFO: loaded from: classes5.dex */
public class Utils {
    public static boolean isLayoutRtl(View view) {
        return ViewCompat.getLayoutDirection(view) == 1;
    }
}
