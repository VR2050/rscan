package U1;

import android.content.Context;
import android.content.ContextWrapper;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class a {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final a f2803a = new a();

    private a() {
    }

    public static final Object a(Context context, Class cls) {
        Context baseContext;
        j.f(cls, "clazz");
        while (!cls.isInstance(context)) {
            if (!(context instanceof ContextWrapper) || context == (baseContext = ((ContextWrapper) context).getBaseContext())) {
                return null;
            }
            context = baseContext;
        }
        return context;
    }
}
