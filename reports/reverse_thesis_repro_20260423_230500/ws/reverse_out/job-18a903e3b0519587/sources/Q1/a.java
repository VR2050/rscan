package Q1;

import android.content.Context;
import android.graphics.Rect;
import android.graphics.Shader;
import com.facebook.react.bridge.ReadableMap;

/* JADX INFO: loaded from: classes.dex */
public final class a {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final l f2400a;

    public a(ReadableMap readableMap, Context context) {
        t2.j.f(context, "context");
        l lVar = null;
        if (readableMap != null) {
            try {
                lVar = new l(readableMap, context);
            } catch (IllegalArgumentException unused) {
            }
        }
        this.f2400a = lVar;
    }

    public final Shader a(Rect rect) {
        t2.j.f(rect, "bounds");
        l lVar = this.f2400a;
        if (lVar != null) {
            return lVar.a(rect);
        }
        return null;
    }
}
