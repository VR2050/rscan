package com.blankj.utilcode.util;

import android.R;
import android.app.Activity;
import android.content.Context;
import android.content.res.Resources;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Point;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.os.Handler;
import android.os.Message;
import android.text.TextUtils;
import android.util.AttributeSet;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.RelativeLayout;
import android.widget.Toast;
import androidx.annotation.CallSuper;
import androidx.annotation.NonNull;
import com.gyf.immersionbar.Constants;
import java.lang.ref.WeakReference;
import java.lang.reflect.Field;
import java.util.Objects;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p139f.p140a.p142b.C1540j;
import p005b.p139f.p140a.p142b.C1544n;
import p005b.p139f.p140a.p142b.C1545o;
import p005b.p139f.p140a.p142b.C1549s;
import p005b.p139f.p140a.p142b.C1550t;
import p005b.p139f.p140a.p142b.RunnableC1547q;
import p005b.p139f.p140a.p142b.RunnableC1548r;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* loaded from: classes.dex */
public final class ToastUtils {

    /* renamed from: a */
    public static final ToastUtils f8825a = new ToastUtils();

    /* renamed from: b */
    public static WeakReference<InterfaceC3217c> f8826b;

    /* renamed from: c */
    public Drawable[] f8827c = new Drawable[4];

    public static final class UtilsMaxWidthRelativeLayout extends RelativeLayout {

        /* renamed from: c */
        public static final int f8828c = C4195m.m4785R(80.0f);

        public UtilsMaxWidthRelativeLayout(Context context) {
            super(context);
        }

        @Override // android.widget.RelativeLayout, android.view.View
        public void onMeasure(int i2, int i3) {
            int i4;
            WindowManager windowManager = (WindowManager) C4195m.m4792Y().getSystemService("window");
            if (windowManager == null) {
                i4 = -1;
            } else {
                Point point = new Point();
                windowManager.getDefaultDisplay().getSize(point);
                i4 = point.x;
            }
            super.onMeasure(View.MeasureSpec.makeMeasureSpec(i4 - f8828c, Integer.MIN_VALUE), i3);
        }

        public UtilsMaxWidthRelativeLayout(Context context, AttributeSet attributeSet) {
            super(context, attributeSet);
        }

        public UtilsMaxWidthRelativeLayout(Context context, AttributeSet attributeSet, int i2) {
            super(context, attributeSet, i2);
        }
    }

    /* renamed from: com.blankj.utilcode.util.ToastUtils$a */
    public static abstract class AbstractC3215a implements InterfaceC3217c {

        /* renamed from: a */
        public Toast f8829a = new Toast(C4195m.m4792Y());

        /* renamed from: b */
        public ToastUtils f8830b;

        /* renamed from: c */
        public View f8831c;

        public AbstractC3215a(ToastUtils toastUtils) {
            this.f8830b = toastUtils;
            ToastUtils toastUtils2 = ToastUtils.f8825a;
            Objects.requireNonNull(toastUtils);
            Objects.requireNonNull(this.f8830b);
            Objects.requireNonNull(this.f8830b);
        }

        /* renamed from: b */
        public View m3884b(int i2) {
            Bitmap createBitmap;
            Bitmap bitmap;
            View view = this.f8831c;
            if (view == null) {
                bitmap = null;
            } else {
                boolean isDrawingCacheEnabled = view.isDrawingCacheEnabled();
                boolean willNotCacheDrawing = view.willNotCacheDrawing();
                view.setDrawingCacheEnabled(true);
                view.setWillNotCacheDrawing(false);
                Bitmap drawingCache = view.getDrawingCache();
                if (drawingCache == null || drawingCache.isRecycled()) {
                    view.measure(View.MeasureSpec.makeMeasureSpec(0, 0), View.MeasureSpec.makeMeasureSpec(0, 0));
                    view.layout(0, 0, view.getMeasuredWidth(), view.getMeasuredHeight());
                    view.buildDrawingCache();
                    Bitmap drawingCache2 = view.getDrawingCache();
                    if (drawingCache2 == null || drawingCache2.isRecycled()) {
                        createBitmap = Bitmap.createBitmap(view.getMeasuredWidth(), view.getMeasuredHeight(), Bitmap.Config.RGB_565);
                        view.draw(new Canvas(createBitmap));
                    } else {
                        createBitmap = Bitmap.createBitmap(drawingCache2);
                    }
                } else {
                    createBitmap = Bitmap.createBitmap(drawingCache);
                }
                view.setWillNotCacheDrawing(willNotCacheDrawing);
                view.setDrawingCacheEnabled(isDrawingCacheEnabled);
                bitmap = createBitmap;
            }
            ImageView imageView = new ImageView(C4195m.m4792Y());
            imageView.setTag("TAG_TOAST" + i2);
            imageView.setImageBitmap(bitmap);
            return imageView;
        }

        /* renamed from: c */
        public final void m3885c() {
            if (TextUtils.getLayoutDirectionFromLocale(Build.VERSION.SDK_INT >= 24 ? C4195m.m4792Y().getResources().getConfiguration().getLocales().get(0) : C4195m.m4792Y().getResources().getConfiguration().locale) == 1) {
                View m3884b = m3884b(-1);
                this.f8831c = m3884b;
                this.f8829a.setView(m3884b);
            }
        }

        @Override // com.blankj.utilcode.util.ToastUtils.InterfaceC3217c
        @CallSuper
        public void cancel() {
            Toast toast = this.f8829a;
            if (toast != null) {
                toast.cancel();
            }
            this.f8829a = null;
            this.f8831c = null;
        }

        /* renamed from: d */
        public void m3886d(View view) {
            this.f8831c = view;
            this.f8829a.setView(view);
        }
    }

    /* renamed from: com.blankj.utilcode.util.ToastUtils$b */
    public static final class C3216b extends AbstractC3215a {

        /* renamed from: d */
        public static int f8832d;

        /* renamed from: e */
        public C1545o f8833e;

        /* renamed from: f */
        public InterfaceC3217c f8834f;

        /* renamed from: com.blankj.utilcode.util.ToastUtils$b$a */
        public class a implements Runnable {
            public a() {
            }

            @Override // java.lang.Runnable
            public void run() {
                C3216b.this.cancel();
            }
        }

        public C3216b(ToastUtils toastUtils) {
            super(toastUtils);
        }

        @Override // com.blankj.utilcode.util.ToastUtils.InterfaceC3217c
        /* renamed from: a */
        public void mo3887a(int i2) {
            if (this.f8829a == null) {
                return;
            }
            if (!(!C1549s.f1795c.f1802k)) {
                this.f8834f = m3888e(i2);
                return;
            }
            boolean z = false;
            for (Activity activity : C1550t.m724a()) {
                if (C1550t.m728e(activity)) {
                    if (z) {
                        m3889f(activity, f8832d, true);
                    } else {
                        C3219e c3219e = new C3219e(this.f8830b, activity.getWindowManager(), 99);
                        c3219e.f8831c = m3884b(-1);
                        c3219e.f8829a = this.f8829a;
                        c3219e.mo3887a(i2);
                        this.f8834f = c3219e;
                        z = true;
                    }
                }
            }
            if (!z) {
                this.f8834f = m3888e(i2);
                return;
            }
            C1544n c1544n = new C1544n(this, f8832d);
            this.f8833e = c1544n;
            C1549s c1549s = C1549s.f1795c;
            Objects.requireNonNull(c1549s);
            Activity activity2 = C1549s.f1796e;
            if (activity2 != null) {
                C1550t.m731h(new RunnableC1547q(c1549s, activity2, c1544n));
            }
            C1540j.f1772a.postDelayed(new a(), i2 == 0 ? 2000L : 3500L);
            f8832d++;
        }

        @Override // com.blankj.utilcode.util.ToastUtils.AbstractC3215a, com.blankj.utilcode.util.ToastUtils.InterfaceC3217c
        public void cancel() {
            Window window;
            C1545o c1545o = this.f8833e;
            if (c1545o != null) {
                C1549s c1549s = C1549s.f1795c;
                Objects.requireNonNull(c1549s);
                Activity activity = C1549s.f1796e;
                if (activity != null && c1545o != null) {
                    C1550t.m731h(new RunnableC1548r(c1549s, activity, c1545o));
                }
                this.f8833e = null;
                for (Activity activity2 : C1550t.m724a()) {
                    if (C1550t.m728e(activity2) && (window = activity2.getWindow()) != null) {
                        ViewGroup viewGroup = (ViewGroup) window.getDecorView();
                        StringBuilder m586H = C1499a.m586H("TAG_TOAST");
                        m586H.append(f8832d - 1);
                        View findViewWithTag = viewGroup.findViewWithTag(m586H.toString());
                        if (findViewWithTag != null) {
                            try {
                                viewGroup.removeView(findViewWithTag);
                            } catch (Exception unused) {
                            }
                        }
                    }
                }
            }
            InterfaceC3217c interfaceC3217c = this.f8834f;
            if (interfaceC3217c != null) {
                interfaceC3217c.cancel();
                this.f8834f = null;
            }
            super.cancel();
        }

        /* renamed from: e */
        public final InterfaceC3217c m3888e(int i2) {
            C3218d c3218d = new C3218d(this.f8830b);
            Toast toast = this.f8829a;
            c3218d.f8829a = toast;
            if (toast != null) {
                toast.setDuration(i2);
                c3218d.f8829a.show();
            }
            return c3218d;
        }

        /* renamed from: f */
        public final void m3889f(Activity activity, int i2, boolean z) {
            Window window = activity.getWindow();
            if (window != null) {
                ViewGroup viewGroup = (ViewGroup) window.getDecorView();
                FrameLayout.LayoutParams layoutParams = new FrameLayout.LayoutParams(-2, -2);
                layoutParams.gravity = this.f8829a.getGravity();
                int yOffset = this.f8829a.getYOffset();
                Resources system = Resources.getSystem();
                int identifier = system.getIdentifier(Constants.IMMERSION_NAVIGATION_BAR_HEIGHT, "dimen", "android");
                layoutParams.bottomMargin = yOffset + (identifier != 0 ? system.getDimensionPixelSize(identifier) : 0);
                int yOffset2 = this.f8829a.getYOffset();
                Resources system2 = Resources.getSystem();
                layoutParams.topMargin = yOffset2 + system2.getDimensionPixelSize(system2.getIdentifier(Constants.IMMERSION_STATUS_BAR_HEIGHT, "dimen", "android"));
                layoutParams.leftMargin = this.f8829a.getXOffset();
                View m3884b = m3884b(i2);
                if (z) {
                    m3884b.setAlpha(0.0f);
                    m3884b.animate().alpha(1.0f).setDuration(200L).start();
                }
                viewGroup.addView(m3884b, layoutParams);
            }
        }
    }

    /* renamed from: com.blankj.utilcode.util.ToastUtils$c */
    public interface InterfaceC3217c {
        /* renamed from: a */
        void mo3887a(int i2);

        void cancel();
    }

    /* renamed from: com.blankj.utilcode.util.ToastUtils$d */
    public static final class C3218d extends AbstractC3215a {

        /* renamed from: com.blankj.utilcode.util.ToastUtils$d$a */
        public static class a extends Handler {

            /* renamed from: a */
            public Handler f8836a;

            public a(Handler handler) {
                this.f8836a = handler;
            }

            @Override // android.os.Handler
            public void dispatchMessage(@NonNull Message message) {
                try {
                    this.f8836a.dispatchMessage(message);
                } catch (Exception e2) {
                    e2.printStackTrace();
                }
            }

            @Override // android.os.Handler
            public void handleMessage(@NonNull Message message) {
                this.f8836a.handleMessage(message);
            }
        }

        public C3218d(ToastUtils toastUtils) {
            super(toastUtils);
            if (Build.VERSION.SDK_INT == 25) {
                try {
                    Field declaredField = Toast.class.getDeclaredField("mTN");
                    declaredField.setAccessible(true);
                    Object obj = declaredField.get(this.f8829a);
                    Field declaredField2 = declaredField.getType().getDeclaredField("mHandler");
                    declaredField2.setAccessible(true);
                    declaredField2.set(obj, new a((Handler) declaredField2.get(obj)));
                } catch (Exception unused) {
                }
            }
        }

        @Override // com.blankj.utilcode.util.ToastUtils.InterfaceC3217c
        /* renamed from: a */
        public void mo3887a(int i2) {
            Toast toast = this.f8829a;
            if (toast == null) {
                return;
            }
            toast.setDuration(i2);
            this.f8829a.show();
        }
    }

    /* renamed from: com.blankj.utilcode.util.ToastUtils$e */
    public static final class C3219e extends AbstractC3215a {

        /* renamed from: d */
        public WindowManager f8837d;

        /* renamed from: e */
        public WindowManager.LayoutParams f8838e;

        /* renamed from: com.blankj.utilcode.util.ToastUtils$e$a */
        public class a implements Runnable {
            public a() {
            }

            @Override // java.lang.Runnable
            public void run() {
                C3219e.this.cancel();
            }
        }

        public C3219e(ToastUtils toastUtils, int i2) {
            super(toastUtils);
            this.f8838e = new WindowManager.LayoutParams();
            this.f8837d = (WindowManager) C4195m.m4792Y().getSystemService("window");
            this.f8838e.type = i2;
        }

        @Override // com.blankj.utilcode.util.ToastUtils.InterfaceC3217c
        /* renamed from: a */
        public void mo3887a(int i2) {
            if (this.f8829a == null) {
                return;
            }
            WindowManager.LayoutParams layoutParams = this.f8838e;
            layoutParams.height = -2;
            layoutParams.width = -2;
            layoutParams.format = -3;
            layoutParams.windowAnimations = R.style.Animation.Toast;
            layoutParams.setTitle("ToastWithoutNotification");
            WindowManager.LayoutParams layoutParams2 = this.f8838e;
            layoutParams2.flags = 152;
            layoutParams2.packageName = C4195m.m4792Y().getPackageName();
            this.f8838e.gravity = this.f8829a.getGravity();
            WindowManager.LayoutParams layoutParams3 = this.f8838e;
            int i3 = layoutParams3.gravity;
            if ((i3 & 7) == 7) {
                layoutParams3.horizontalWeight = 1.0f;
            }
            if ((i3 & 112) == 112) {
                layoutParams3.verticalWeight = 1.0f;
            }
            layoutParams3.x = this.f8829a.getXOffset();
            this.f8838e.y = this.f8829a.getYOffset();
            this.f8838e.horizontalMargin = this.f8829a.getHorizontalMargin();
            this.f8838e.verticalMargin = this.f8829a.getVerticalMargin();
            try {
                WindowManager windowManager = this.f8837d;
                if (windowManager != null) {
                    windowManager.addView(this.f8831c, this.f8838e);
                }
            } catch (Exception unused) {
            }
            C1540j.f1772a.postDelayed(new a(), i2 == 0 ? 2000L : 3500L);
        }

        @Override // com.blankj.utilcode.util.ToastUtils.AbstractC3215a, com.blankj.utilcode.util.ToastUtils.InterfaceC3217c
        public void cancel() {
            try {
                WindowManager windowManager = this.f8837d;
                if (windowManager != null) {
                    windowManager.removeViewImmediate(this.f8831c);
                    this.f8837d = null;
                }
            } catch (Exception unused) {
            }
            super.cancel();
        }

        public C3219e(ToastUtils toastUtils, WindowManager windowManager, int i2) {
            super(toastUtils);
            WindowManager.LayoutParams layoutParams = new WindowManager.LayoutParams();
            this.f8838e = layoutParams;
            this.f8837d = windowManager;
            layoutParams.type = i2;
        }
    }
}
