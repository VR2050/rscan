package p005b.p143g.p144a.p166q.p167i;

import android.content.Context;
import android.graphics.Point;
import android.graphics.drawable.Drawable;
import android.util.Log;
import android.view.Display;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewTreeObserver;
import android.view.WindowManager;
import androidx.annotation.IdRes;
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

/* renamed from: b.g.a.q.i.d */
/* loaded from: classes.dex */
public abstract class AbstractC1785d<T extends View, Z> implements InterfaceC1790i<Z> {

    /* renamed from: c */
    @IdRes
    public static final int f2719c = R$id.glide_custom_view_target_tag;

    /* renamed from: e */
    public final a f2720e;

    /* renamed from: f */
    public final T f2721f;

    @VisibleForTesting
    /* renamed from: b.g.a.q.i.d$a */
    public static final class a {

        /* renamed from: a */
        @Nullable
        @VisibleForTesting
        public static Integer f2722a;

        /* renamed from: b */
        public final View f2723b;

        /* renamed from: c */
        public final List<InterfaceC1789h> f2724c = new ArrayList();

        /* renamed from: d */
        @Nullable
        public ViewTreeObserverOnPreDrawListenerC5112a f2725d;

        /* renamed from: b.g.a.q.i.d$a$a, reason: collision with other inner class name */
        public static final class ViewTreeObserverOnPreDrawListenerC5112a implements ViewTreeObserver.OnPreDrawListener {

            /* renamed from: c */
            public final WeakReference<a> f2726c;

            public ViewTreeObserverOnPreDrawListenerC5112a(@NonNull a aVar) {
                this.f2726c = new WeakReference<>(aVar);
            }

            @Override // android.view.ViewTreeObserver.OnPreDrawListener
            public boolean onPreDraw() {
                if (Log.isLoggable("CustomViewTarget", 2)) {
                    String str = "OnGlobalLayoutListener called attachStateListener=" + this;
                }
                a aVar = this.f2726c.get();
                if (aVar == null || aVar.f2724c.isEmpty()) {
                    return true;
                }
                int m1126d = aVar.m1126d();
                int m1125c = aVar.m1125c();
                if (!aVar.m1127e(m1126d, m1125c)) {
                    return true;
                }
                Iterator it = new ArrayList(aVar.f2724c).iterator();
                while (it.hasNext()) {
                    ((InterfaceC1789h) it.next()).mo1111a(m1126d, m1125c);
                }
                aVar.m1123a();
                return true;
            }
        }

        public a(@NonNull View view) {
            this.f2723b = view;
        }

        /* renamed from: a */
        public void m1123a() {
            ViewTreeObserver viewTreeObserver = this.f2723b.getViewTreeObserver();
            if (viewTreeObserver.isAlive()) {
                viewTreeObserver.removeOnPreDrawListener(this.f2725d);
            }
            this.f2725d = null;
            this.f2724c.clear();
        }

        /* renamed from: b */
        public final int m1124b(int i2, int i3, int i4) {
            int i5 = i3 - i4;
            if (i5 > 0) {
                return i5;
            }
            int i6 = i2 - i4;
            if (i6 > 0) {
                return i6;
            }
            if (this.f2723b.isLayoutRequested() || i3 != -2) {
                return 0;
            }
            Log.isLoggable("CustomViewTarget", 4);
            Context context = this.f2723b.getContext();
            if (f2722a == null) {
                WindowManager windowManager = (WindowManager) context.getSystemService("window");
                Objects.requireNonNull(windowManager, "Argument must not be null");
                Display defaultDisplay = windowManager.getDefaultDisplay();
                Point point = new Point();
                defaultDisplay.getSize(point);
                f2722a = Integer.valueOf(Math.max(point.x, point.y));
            }
            return f2722a.intValue();
        }

        /* renamed from: c */
        public final int m1125c() {
            int paddingBottom = this.f2723b.getPaddingBottom() + this.f2723b.getPaddingTop();
            ViewGroup.LayoutParams layoutParams = this.f2723b.getLayoutParams();
            return m1124b(this.f2723b.getHeight(), layoutParams != null ? layoutParams.height : 0, paddingBottom);
        }

        /* renamed from: d */
        public final int m1126d() {
            int paddingRight = this.f2723b.getPaddingRight() + this.f2723b.getPaddingLeft();
            ViewGroup.LayoutParams layoutParams = this.f2723b.getLayoutParams();
            return m1124b(this.f2723b.getWidth(), layoutParams != null ? layoutParams.width : 0, paddingRight);
        }

        /* renamed from: e */
        public final boolean m1127e(int i2, int i3) {
            if (i2 > 0 || i2 == Integer.MIN_VALUE) {
                if (i3 > 0 || i3 == Integer.MIN_VALUE) {
                    return true;
                }
            }
            return false;
        }
    }

    public AbstractC1785d(@NonNull T t) {
        Objects.requireNonNull(t, "Argument must not be null");
        this.f2721f = t;
        this.f2720e = new a(t);
    }

    @Override // p005b.p143g.p144a.p166q.p167i.InterfaceC1790i
    @Nullable
    public final InterfaceC1775b getRequest() {
        Object tag = this.f2721f.getTag(f2719c);
        if (tag == null) {
            return null;
        }
        if (tag instanceof InterfaceC1775b) {
            return (InterfaceC1775b) tag;
        }
        throw new IllegalArgumentException("You must not pass non-R.id ids to setTag(id)");
    }

    @Override // p005b.p143g.p144a.p166q.p167i.InterfaceC1790i
    public final void getSize(@NonNull InterfaceC1789h interfaceC1789h) {
        a aVar = this.f2720e;
        int m1126d = aVar.m1126d();
        int m1125c = aVar.m1125c();
        if (aVar.m1127e(m1126d, m1125c)) {
            ((C1781h) interfaceC1789h).mo1111a(m1126d, m1125c);
            return;
        }
        if (!aVar.f2724c.contains(interfaceC1789h)) {
            aVar.f2724c.add(interfaceC1789h);
        }
        if (aVar.f2725d == null) {
            ViewTreeObserver viewTreeObserver = aVar.f2723b.getViewTreeObserver();
            a.ViewTreeObserverOnPreDrawListenerC5112a viewTreeObserverOnPreDrawListenerC5112a = new a.ViewTreeObserverOnPreDrawListenerC5112a(aVar);
            aVar.f2725d = viewTreeObserverOnPreDrawListenerC5112a;
            viewTreeObserver.addOnPreDrawListener(viewTreeObserverOnPreDrawListenerC5112a);
        }
    }

    @Override // p005b.p143g.p144a.p163n.InterfaceC1755i
    public void onDestroy() {
    }

    @Override // p005b.p143g.p144a.p166q.p167i.InterfaceC1790i
    public final void onLoadCleared(@Nullable Drawable drawable) {
        this.f2720e.m1123a();
    }

    @Override // p005b.p143g.p144a.p166q.p167i.InterfaceC1790i
    public final void onLoadStarted(@Nullable Drawable drawable) {
    }

    @Override // p005b.p143g.p144a.p163n.InterfaceC1755i
    public void onStart() {
    }

    @Override // p005b.p143g.p144a.p163n.InterfaceC1755i
    public void onStop() {
    }

    @Override // p005b.p143g.p144a.p166q.p167i.InterfaceC1790i
    public final void removeCallback(@NonNull InterfaceC1789h interfaceC1789h) {
        this.f2720e.f2724c.remove(interfaceC1789h);
    }

    @Override // p005b.p143g.p144a.p166q.p167i.InterfaceC1790i
    public final void setRequest(@Nullable InterfaceC1775b interfaceC1775b) {
        this.f2721f.setTag(f2719c, interfaceC1775b);
    }

    public String toString() {
        StringBuilder m586H = C1499a.m586H("Target for: ");
        m586H.append(this.f2721f);
        return m586H.toString();
    }
}
