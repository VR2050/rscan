package P1;

import android.os.Handler;
import android.util.SparseArray;
import android.view.View;
import android.view.ViewGroup;
import android.view.animation.Animation;
import com.facebook.react.bridge.Callback;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.UiThreadUtil;

/* JADX INFO: loaded from: classes.dex */
public class e {

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private boolean f2180e;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private Runnable f2182g;

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final P1.a f2176a = new h();

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final P1.a f2177b = new k();

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final P1.a f2178c = new i();

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final SparseArray f2179d = new SparseArray(0);

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private long f2181f = -1;

    class a implements Runnable {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ Callback f2183b;

        a(Callback callback) {
            this.f2183b = callback;
        }

        @Override // java.lang.Runnable
        public void run() {
            this.f2183b.invoke(Boolean.TRUE);
        }
    }

    private void d(View view) {
        view.setClickable(false);
        if (view instanceof ViewGroup) {
            ViewGroup viewGroup = (ViewGroup) view;
            for (int i3 = 0; i3 < viewGroup.getChildCount(); i3++) {
                d(viewGroup.getChildAt(i3));
            }
        }
    }

    private void g(long j3) {
        if (this.f2182g != null) {
            Handler uiThreadHandler = UiThreadUtil.getUiThreadHandler();
            uiThreadHandler.removeCallbacks(this.f2182g);
            uiThreadHandler.postDelayed(this.f2182g, j3);
        }
    }

    public void b(View view, int i3, int i4, int i5, int i6) {
        UiThreadUtil.assertOnUiThread();
        int id = view.getId();
        j jVar = (j) this.f2179d.get(id);
        if (jVar != null) {
            jVar.a(i3, i4, i5, i6);
            return;
        }
        Animation animationA = ((view.getWidth() == 0 || view.getHeight() == 0) ? this.f2176a : this.f2177b).a(view, i3, i4, i5, i6);
        if (animationA instanceof j) {
            animationA.setAnimationListener(new b(id));
        } else {
            view.layout(i3, i4, i5 + i3, i6 + i4);
        }
        if (animationA != null) {
            long duration = animationA.getDuration();
            if (duration > this.f2181f) {
                this.f2181f = duration;
                g(duration);
            }
            view.startAnimation(animationA);
        }
    }

    public void c(View view, f fVar) {
        UiThreadUtil.assertOnUiThread();
        Animation animationA = this.f2178c.a(view, view.getLeft(), view.getTop(), view.getWidth(), view.getHeight());
        if (animationA == null) {
            fVar.a();
            return;
        }
        d(view);
        animationA.setAnimationListener(new c(fVar));
        long duration = animationA.getDuration();
        if (duration > this.f2181f) {
            g(duration);
            this.f2181f = duration;
        }
        view.startAnimation(animationA);
    }

    public void e(ReadableMap readableMap, Callback callback) {
        if (readableMap == null) {
            f();
            return;
        }
        this.f2180e = false;
        int i3 = readableMap.hasKey("duration") ? readableMap.getInt("duration") : 0;
        g gVar = g.f2190c;
        if (readableMap.hasKey(g.b(gVar))) {
            this.f2176a.d(readableMap.getMap(g.b(gVar)), i3);
            this.f2180e = true;
        }
        g gVar2 = g.f2191d;
        if (readableMap.hasKey(g.b(gVar2))) {
            this.f2177b.d(readableMap.getMap(g.b(gVar2)), i3);
            this.f2180e = true;
        }
        g gVar3 = g.f2192e;
        if (readableMap.hasKey(g.b(gVar3))) {
            this.f2178c.d(readableMap.getMap(g.b(gVar3)), i3);
            this.f2180e = true;
        }
        if (!this.f2180e || callback == null) {
            return;
        }
        this.f2182g = new a(callback);
    }

    public void f() {
        this.f2176a.f();
        this.f2177b.f();
        this.f2178c.f();
        this.f2182g = null;
        this.f2180e = false;
        this.f2181f = -1L;
    }

    public boolean h(View view) {
        if (view == null) {
            return false;
        }
        return (this.f2180e && view.getParent() != null) || this.f2179d.get(view.getId()) != null;
    }

    class b implements Animation.AnimationListener {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ int f2185a;

        b(int i3) {
            this.f2185a = i3;
        }

        @Override // android.view.animation.Animation.AnimationListener
        public void onAnimationEnd(Animation animation) {
            e.this.f2179d.remove(this.f2185a);
        }

        /* JADX WARN: Multi-variable type inference failed */
        @Override // android.view.animation.Animation.AnimationListener
        public void onAnimationStart(Animation animation) {
            e.this.f2179d.put(this.f2185a, (j) animation);
        }

        @Override // android.view.animation.Animation.AnimationListener
        public void onAnimationRepeat(Animation animation) {
        }
    }

    class c implements Animation.AnimationListener {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ f f2187a;

        c(f fVar) {
            this.f2187a = fVar;
        }

        @Override // android.view.animation.Animation.AnimationListener
        public void onAnimationEnd(Animation animation) {
            this.f2187a.a();
        }

        @Override // android.view.animation.Animation.AnimationListener
        public void onAnimationRepeat(Animation animation) {
        }

        @Override // android.view.animation.Animation.AnimationListener
        public void onAnimationStart(Animation animation) {
        }
    }
}
