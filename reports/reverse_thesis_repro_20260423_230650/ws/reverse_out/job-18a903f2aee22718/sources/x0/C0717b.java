package x0;

import android.graphics.PointF;
import android.graphics.Rect;
import android.net.Uri;
import java.util.Map;
import t2.j;
import y0.InterfaceC0723b;

/* JADX INFO: renamed from: x0.b, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class C0717b {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final C0717b f10365a = new C0717b();

    private C0717b() {
    }

    public static final InterfaceC0723b.a a(Map map, Map map2, Map map3, Map map4, Rect rect, String str, PointF pointF, Map map5, Object obj, boolean z3, Uri uri) {
        j.f(map, "componentAttribution");
        j.f(map2, "shortcutAttribution");
        InterfaceC0723b.a aVar = new InterfaceC0723b.a();
        if (rect != null) {
            aVar.f10383h = rect.width();
            aVar.f10384i = rect.height();
        }
        aVar.f10385j = str;
        if (pointF != null) {
            aVar.f10386k = Float.valueOf(pointF.x);
            aVar.f10387l = Float.valueOf(pointF.y);
        }
        aVar.f10381f = obj;
        aVar.f10388m = z3;
        aVar.f10382g = uri;
        aVar.f10378c = map3;
        aVar.f10379d = map5;
        aVar.f10377b = map2;
        aVar.f10376a = map;
        aVar.f10380e = map4;
        return aVar;
    }
}
