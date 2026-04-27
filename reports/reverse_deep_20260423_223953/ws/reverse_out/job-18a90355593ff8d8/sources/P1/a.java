package P1;

import android.view.View;
import android.view.animation.AccelerateDecelerateInterpolator;
import android.view.animation.AccelerateInterpolator;
import android.view.animation.Animation;
import android.view.animation.DecelerateInterpolator;
import android.view.animation.Interpolator;
import android.view.animation.LinearInterpolator;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.uimanager.P;
import d1.AbstractC0508d;
import java.util.Map;

/* JADX INFO: loaded from: classes.dex */
abstract class a {

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private static final Map f2155e = AbstractC0508d.g(d.f2169c, new LinearInterpolator(), d.f2170d, new AccelerateInterpolator(), d.f2171e, new DecelerateInterpolator(), d.f2172f, new AccelerateDecelerateInterpolator());

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private Interpolator f2156a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private int f2157b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    protected b f2158c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    protected int f2159d;

    a() {
    }

    private static Interpolator c(d dVar, ReadableMap readableMap) {
        Interpolator nVar = dVar.equals(d.f2173g) ? new n(n.a(readableMap)) : (Interpolator) f2155e.get(dVar);
        if (nVar != null) {
            return nVar;
        }
        throw new IllegalArgumentException("Missing interpolator for type : " + dVar);
    }

    public final Animation a(View view, int i3, int i4, int i5, int i6) {
        if (!e()) {
            return null;
        }
        Animation animationB = b(view, i3, i4, i5, i6);
        if (animationB != null) {
            animationB.setDuration(this.f2159d);
            animationB.setStartOffset(this.f2157b);
            animationB.setInterpolator(this.f2156a);
        }
        return animationB;
    }

    abstract Animation b(View view, int i3, int i4, int i5, int i6);

    public void d(ReadableMap readableMap, int i3) {
        this.f2158c = readableMap.hasKey("property") ? b.b(readableMap.getString("property")) : null;
        if (readableMap.hasKey("duration")) {
            i3 = readableMap.getInt("duration");
        }
        this.f2159d = i3;
        this.f2157b = readableMap.hasKey("delay") ? readableMap.getInt("delay") : 0;
        if (!readableMap.hasKey("type")) {
            throw new IllegalArgumentException("Missing interpolation type.");
        }
        this.f2156a = c(d.b(readableMap.getString("type")), readableMap);
        if (e()) {
            return;
        }
        throw new P("Invalid layout animation : " + readableMap);
    }

    abstract boolean e();

    public void f() {
        this.f2158c = null;
        this.f2159d = 0;
        this.f2157b = 0;
        this.f2156a = null;
    }
}
