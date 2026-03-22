package p005b.p143g.p144a.p166q.p167i;

import android.content.Context;
import android.graphics.Point;
import android.util.Log;
import android.view.Display;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewTreeObserver;
import android.view.WindowManager;
import androidx.annotation.CallSuper;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.VisibleForTesting;
import com.bumptech.glide.R$id;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p143g.p144a.p166q.C1781h;
import p005b.p143g.p144a.p166q.InterfaceC1775b;

@Deprecated
/* renamed from: b.g.a.q.i.j */
/* loaded from: classes.dex */
public abstract class AbstractC1791j<T extends View, Z> extends AbstractC1782a<Z> {

    /* renamed from: c */
    public static int f2728c = R$id.glide_custom_view_target_tag;

    /* renamed from: e */
    public final T f2729e;

    /* renamed from: f */
    public final a f2730f;

    @VisibleForTesting
    /* renamed from: b.g.a.q.i.j$a */
    public static final class a {

        /* renamed from: a */
        @Nullable
        @VisibleForTesting
        public static Integer f2731a;

        /* renamed from: b */
        public final View f2732b;

        /* renamed from: c */
        public final List<InterfaceC1789h> f2733c = new ArrayList();

        /* renamed from: d */
        @Nullable
        public ViewTreeObserverOnPreDrawListenerC5113a f2734d;

        /* renamed from: b.g.a.q.i.j$a$a, reason: collision with other inner class name */
        public static final class ViewTreeObserverOnPreDrawListenerC5113a implements ViewTreeObserver.OnPreDrawListener {

            /* renamed from: c */
            public final WeakReference<a> f2735c;

            public ViewTreeObserverOnPreDrawListenerC5113a(@NonNull a aVar) {
                this.f2735c = new WeakReference<>(aVar);
            }

            @Override // android.view.ViewTreeObserver.OnPreDrawListener
            public boolean onPreDraw() {
                if (Log.isLoggable("ViewTarget", 2)) {
                    String str = "OnGlobalLayoutListener called attachStateListener=" + this;
                }
                a aVar = this.f2735c.get();
                if (aVar == null || aVar.f2733c.isEmpty()) {
                    return true;
                }
                int m1132d = aVar.m1132d();
                int m1131c = aVar.m1131c();
                if (!aVar.m1133e(m1132d, m1131c)) {
                    return true;
                }
                Iterator it = new ArrayList(aVar.f2733c).iterator();
                while (it.hasNext()) {
                    ((InterfaceC1789h) it.next()).mo1111a(m1132d, m1131c);
                }
                aVar.m1129a();
                return true;
            }
        }

        public a(@NonNull View view) {
            this.f2732b = view;
        }

        /* renamed from: a */
        public void m1129a() {
            ViewTreeObserver viewTreeObserver = this.f2732b.getViewTreeObserver();
            if (viewTreeObserver.isAlive()) {
                viewTreeObserver.removeOnPreDrawListener(this.f2734d);
            }
            this.f2734d = null;
            this.f2733c.clear();
        }

        /* renamed from: b */
        public final int m1130b(int i2, int i3, int i4) {
            int i5 = i3 - i4;
            if (i5 > 0) {
                return i5;
            }
            int i6 = i2 - i4;
            if (i6 > 0) {
                return i6;
            }
            if (this.f2732b.isLayoutRequested() || i3 != -2) {
                return 0;
            }
            Log.isLoggable("ViewTarget", 4);
            Context context = this.f2732b.getContext();
            if (f2731a == null) {
                WindowManager windowManager = (WindowManager) context.getSystemService("window");
                Objects.requireNonNull(windowManager, "Argument must not be null");
                Display defaultDisplay = windowManager.getDefaultDisplay();
                Point point = new Point();
                defaultDisplay.getSize(point);
                f2731a = Integer.valueOf(Math.max(point.x, point.y));
            }
            return f2731a.intValue();
        }

        /* renamed from: c */
        public final int m1131c() {
            int paddingBottom = this.f2732b.getPaddingBottom() + this.f2732b.getPaddingTop();
            ViewGroup.LayoutParams layoutParams = this.f2732b.getLayoutParams();
            return m1130b(this.f2732b.getHeight(), layoutParams != null ? layoutParams.height : 0, paddingBottom);
        }

        /* renamed from: d */
        public final int m1132d() {
            int paddingRight = this.f2732b.getPaddingRight() + this.f2732b.getPaddingLeft();
            ViewGroup.LayoutParams layoutParams = this.f2732b.getLayoutParams();
            return m1130b(this.f2732b.getWidth(), layoutParams != null ? layoutParams.width : 0, paddingRight);
        }

        /* renamed from: e */
        public final boolean m1133e(int i2, int i3) {
            if (i2 > 0 || i2 == Integer.MIN_VALUE) {
                if (i3 > 0 || i3 == Integer.MIN_VALUE) {
                    return true;
                }
            }
            return false;
        }
    }

    public AbstractC1791j(@NonNull T t) {
        Objects.requireNonNull(t, "Argument must not be null");
        this.f2729e = t;
        this.f2730f = new a(t);
    }

    @Override // p005b.p143g.p144a.p166q.p167i.InterfaceC1790i
    @Nullable
    public InterfaceC1775b getRequest() {
        Object tag = this.f2729e.getTag(f2728c);
        if (tag == null) {
            return null;
        }
        if (tag instanceof InterfaceC1775b) {
            return (InterfaceC1775b) tag;
        }
        throw new IllegalArgumentException("You must not call setTag() on a view Glide is targeting");
    }

    @Override // p005b.p143g.p144a.p166q.p167i.InterfaceC1790i
    @CallSuper
    public void getSize(@NonNull InterfaceC1789h interfaceC1789h) {
        a aVar = this.f2730f;
        int m1132d = aVar.m1132d();
        int m1131c = aVar.m1131c();
        if (aVar.m1133e(m1132d, m1131c)) {
            ((C1781h) interfaceC1789h).mo1111a(m1132d, m1131c);
            return;
        }
        if (!aVar.f2733c.contains(interfaceC1789h)) {
            aVar.f2733c.add(interfaceC1789h);
        }
        if (aVar.f2734d == null) {
            ViewTreeObserver viewTreeObserver = aVar.f2732b.getViewTreeObserver();
            a.ViewTreeObserverOnPreDrawListenerC5113a viewTreeObserverOnPreDrawListenerC5113a = new a.ViewTreeObserverOnPreDrawListenerC5113a(aVar);
            aVar.f2734d = viewTreeObserverOnPreDrawListenerC5113a;
            viewTreeObserver.addOnPreDrawListener(viewTreeObserverOnPreDrawListenerC5113a);
        }
    }

    @Override // p005b.p143g.p144a.p166q.p167i.InterfaceC1790i
    @CallSuper
    public void removeCallback(@NonNull InterfaceC1789h interfaceC1789h) {
        this.f2730f.f2733c.remove(interfaceC1789h);
    }

    @Override // p005b.p143g.p144a.p166q.p167i.InterfaceC1790i
    public void setRequest(@Nullable InterfaceC1775b interfaceC1775b) {
        this.f2729e.setTag(f2728c, interfaceC1775b);
    }

    public String toString() {
        StringBuilder m586H = C1499a.m586H("Target for: ");
        m586H.append(this.f2729e);
        return m586H.toString();
    }
}
