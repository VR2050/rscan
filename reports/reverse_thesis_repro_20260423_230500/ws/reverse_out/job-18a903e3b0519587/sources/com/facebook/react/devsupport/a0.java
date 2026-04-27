package com.facebook.react.devsupport;

import android.app.Dialog;
import android.content.Context;
import android.graphics.drawable.ColorDrawable;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import android.widget.TextView;
import c1.AbstractC0338j;
import c1.AbstractC0339k;
import c1.AbstractC0341m;
import c1.AbstractC0343o;
import com.facebook.react.bridge.UiThreadUtil;
import j1.e;

/* JADX INFO: loaded from: classes.dex */
public final class a0 implements j1.h {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final q.i f6797a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private Dialog f6798b;

    public a0(q.i iVar) {
        t2.j.f(iVar, "contextSupplier");
        this.f6797a = iVar;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void e(a0 a0Var) {
        Dialog dialog = a0Var.f6798b;
        if (dialog != null) {
            dialog.dismiss();
        }
        a0Var.f6798b = null;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void f(a0 a0Var, String str, final e.a aVar) {
        Dialog dialog = a0Var.f6798b;
        if (dialog != null) {
            dialog.dismiss();
        }
        Context context = (Context) a0Var.f6797a.get();
        if (context == null) {
            return;
        }
        View viewInflate = LayoutInflater.from(context).inflate(AbstractC0341m.f5607d, (ViewGroup) null);
        t2.j.e(viewInflate, "inflate(...)");
        viewInflate.findViewById(AbstractC0339k.f5588l).setOnClickListener(new View.OnClickListener() { // from class: com.facebook.react.devsupport.Z
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                a0.g(aVar, view);
            }
        });
        ((TextView) viewInflate.findViewById(AbstractC0339k.f5589m)).setText(str);
        Dialog dialog2 = new Dialog(context, AbstractC0343o.f5648a);
        dialog2.setContentView(viewInflate);
        dialog2.setCancelable(false);
        a0Var.f6798b = dialog2;
        Window window = dialog2.getWindow();
        if (window != null) {
            WindowManager.LayoutParams attributes = window.getAttributes();
            t2.j.e(attributes, "getAttributes(...)");
            attributes.dimAmount = 0.2f;
            window.setAttributes(attributes);
            window.addFlags(2);
            window.setGravity(48);
            window.setElevation(0.0f);
            window.setBackgroundDrawable(new ColorDrawable(0));
            window.setBackgroundDrawableResource(AbstractC0338j.f5571a);
        }
        Dialog dialog3 = a0Var.f6798b;
        if (dialog3 != null) {
            dialog3.show();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void g(e.a aVar, View view) {
        aVar.a();
    }

    @Override // j1.h
    public void d() {
        UiThreadUtil.runOnUiThread(new Runnable() { // from class: com.facebook.react.devsupport.Y
            @Override // java.lang.Runnable
            public final void run() {
                a0.e(this.f6795b);
            }
        });
    }

    @Override // j1.h
    public void h(final String str, final e.a aVar) {
        t2.j.f(str, "message");
        t2.j.f(aVar, "listener");
        UiThreadUtil.runOnUiThread(new Runnable() { // from class: com.facebook.react.devsupport.X
            @Override // java.lang.Runnable
            public final void run() {
                a0.f(this.f6792b, str, aVar);
            }
        });
    }
}
