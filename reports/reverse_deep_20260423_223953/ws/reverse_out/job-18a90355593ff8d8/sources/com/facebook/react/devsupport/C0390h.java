package com.facebook.react.devsupport;

import android.app.Activity;
import android.graphics.Rect;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.widget.PopupWindow;
import android.widget.TextView;
import c1.AbstractC0341m;
import com.facebook.react.bridge.UiThreadUtil;
import j1.InterfaceC0594c;
import java.util.Arrays;
import java.util.Locale;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: renamed from: com.facebook.react.devsupport.h, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class C0390h implements InterfaceC0594c {

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    public static final a f6843d = new a(null);

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private static boolean f6844e = true;

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final c0 f6845a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private TextView f6846b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private PopupWindow f6847c;

    /* JADX INFO: renamed from: com.facebook.react.devsupport.h$a */
    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private a() {
        }
    }

    public C0390h(c0 c0Var) {
        t2.j.f(c0Var, "reactInstanceDevHelper");
        this.f6845a = c0Var;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void g(C0390h c0390h) {
        c0390h.h();
    }

    private final void h() {
        PopupWindow popupWindow = this.f6847c;
        if (popupWindow != null && popupWindow.isShowing()) {
            popupWindow.dismiss();
            this.f6847c = null;
            this.f6846b = null;
        }
    }

    private final void i(String str) {
        PopupWindow popupWindow = this.f6847c;
        if (popupWindow == null || !popupWindow.isShowing()) {
            Activity activityI = this.f6845a.i();
            if (activityI == null) {
                Y.a.m("ReactNative", "Unable to display loading message because react activity isn't available");
                return;
            }
            try {
                Rect rect = new Rect();
                activityI.getWindow().getDecorView().getWindowVisibleDisplayFrame(rect);
                int i3 = rect.top;
                Object systemService = activityI.getSystemService("layout_inflater");
                t2.j.d(systemService, "null cannot be cast to non-null type android.view.LayoutInflater");
                View viewInflate = ((LayoutInflater) systemService).inflate(AbstractC0341m.f5605b, (ViewGroup) null);
                t2.j.d(viewInflate, "null cannot be cast to non-null type android.widget.TextView");
                TextView textView = (TextView) viewInflate;
                textView.setText(str);
                PopupWindow popupWindow2 = new PopupWindow(textView, -1, -2);
                popupWindow2.setTouchable(false);
                popupWindow2.showAtLocation(activityI.getWindow().getDecorView(), 0, 0, i3);
                this.f6846b = textView;
                this.f6847c = popupWindow2;
            } catch (WindowManager.BadTokenException unused) {
                Y.a.m("ReactNative", "Unable to display loading message because react activity isn't active, message: " + str);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void j(C0390h c0390h, String str) {
        c0390h.i(str);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void k(Integer num, Integer num2, C0390h c0390h, String str) {
        String str2;
        if (num == null || num2 == null || num2.intValue() <= 0) {
            str2 = "";
        } else {
            t2.w wVar = t2.w.f10219a;
            str2 = String.format(Locale.getDefault(), " %.1f%%", Arrays.copyOf(new Object[]{Float.valueOf((num.intValue() / num2.intValue()) * 100)}, 1));
            t2.j.e(str2, "format(...)");
        }
        TextView textView = c0390h.f6846b;
        if (textView != null) {
            if (str == null) {
                str = "Loading";
            }
            textView.setText(str + str2 + "…");
        }
    }

    @Override // j1.InterfaceC0594c
    public void a(final String str) {
        t2.j.f(str, "message");
        if (f6844e) {
            UiThreadUtil.runOnUiThread(new Runnable() { // from class: com.facebook.react.devsupport.g
                @Override // java.lang.Runnable
                public final void run() {
                    C0390h.j(this.f6828b, str);
                }
            });
        }
    }

    @Override // j1.InterfaceC0594c
    public void b(final String str, final Integer num, final Integer num2) {
        if (f6844e) {
            UiThreadUtil.runOnUiThread(new Runnable() { // from class: com.facebook.react.devsupport.e
                @Override // java.lang.Runnable
                public final void run() {
                    C0390h.k(num, num2, this, str);
                }
            });
        }
    }

    @Override // j1.InterfaceC0594c
    public void c() {
        if (f6844e) {
            UiThreadUtil.runOnUiThread(new Runnable() { // from class: com.facebook.react.devsupport.f
                @Override // java.lang.Runnable
                public final void run() {
                    C0390h.g(this.f6826b);
                }
            });
        }
    }
}
