package R1;

import android.view.View;
import android.view.ViewGroup;
import androidx.activity.result.d;
import c1.AbstractC0339k;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class a {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final a f2633a = new a();

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private static final List f2634b = new ArrayList();

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private static final Map f2635c = new HashMap();

    private a() {
    }

    public static final View a(View view, String str) {
        j.f(view, "root");
        j.f(str, "nativeId");
        if (j.b(f2633a.b(view), str)) {
            return view;
        }
        if (!(view instanceof ViewGroup)) {
            return null;
        }
        ViewGroup viewGroup = (ViewGroup) view;
        int childCount = viewGroup.getChildCount();
        for (int i3 = 0; i3 < childCount; i3++) {
            View childAt = viewGroup.getChildAt(i3);
            j.e(childAt, "getChildAt(...)");
            View viewA = a(childAt, str);
            if (viewA != null) {
                return viewA;
            }
        }
        return null;
    }

    private final String b(View view) {
        Object tag = view.getTag(AbstractC0339k.f5576E);
        if (tag instanceof String) {
            return (String) tag;
        }
        return null;
    }

    public static final void c(View view) {
        j.f(view, "view");
        String strB = f2633a.b(view);
        if (strB == null) {
            return;
        }
        Iterator it = f2634b.iterator();
        if (it.hasNext()) {
            d.a(it.next());
            throw null;
        }
        for (Map.Entry entry : f2635c.entrySet()) {
            d.a(entry.getKey());
            if (((Set) entry.getValue()).contains(strB)) {
                throw null;
            }
        }
    }
}
