package androidx.databinding.adapters;

import android.util.SparseArray;
import android.view.View;
import java.lang.ref.WeakReference;
import java.util.WeakHashMap;

/* loaded from: classes.dex */
public class ListenerUtil {
    private static final SparseArray<WeakHashMap<View, WeakReference<?>>> sListeners = new SparseArray<>();

    public static <T> T getListener(View view, int i2) {
        return (T) view.getTag(i2);
    }

    public static <T> T trackListener(View view, T t, int i2) {
        T t2 = (T) view.getTag(i2);
        view.setTag(i2, t);
        return t2;
    }
}
