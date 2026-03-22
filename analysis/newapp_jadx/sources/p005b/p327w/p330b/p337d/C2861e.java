package p005b.p327w.p330b.p337d;

import android.R;
import android.content.res.Resources;
import android.graphics.Rect;
import android.view.View;
import android.view.Window;
import android.view.inputmethod.InputMethodManager;
import androidx.annotation.NonNull;
import com.gyf.immersionbar.Constants;
import p005b.p327w.p330b.C2827a;

/* renamed from: b.w.b.d.e */
/* loaded from: classes2.dex */
public class C2861e {

    /* renamed from: a */
    public static int f7795a;

    /* renamed from: a */
    public static int m3303a(Window window) {
        View findViewById = window.findViewById(R.id.content);
        if (findViewById == null) {
            return 0;
        }
        Rect rect = new Rect();
        findViewById.getWindowVisibleDisplayFrame(rect);
        findViewById.getBottom();
        int abs = Math.abs(findViewById.getBottom() - rect.bottom);
        if (abs <= m3304b() + m3305c()) {
            return 0;
        }
        return abs;
    }

    /* renamed from: b */
    public static int m3304b() {
        Resources resources = C2827a.f7670a.getResources();
        int identifier = resources.getIdentifier(Constants.IMMERSION_NAVIGATION_BAR_HEIGHT, "dimen", "android");
        if (identifier != 0) {
            return resources.getDimensionPixelSize(identifier);
        }
        return 0;
    }

    /* renamed from: c */
    public static int m3305c() {
        Resources resources = C2827a.f7670a.getResources();
        return resources.getDimensionPixelSize(resources.getIdentifier(Constants.IMMERSION_STATUS_BAR_HEIGHT, "dimen", "android"));
    }

    /* renamed from: d */
    public static void m3306d(@NonNull View view) {
        InputMethodManager inputMethodManager = (InputMethodManager) C2827a.f7670a.getSystemService("input_method");
        if (inputMethodManager == null) {
            return;
        }
        inputMethodManager.hideSoftInputFromWindow(view.getWindowToken(), 0);
    }
}
