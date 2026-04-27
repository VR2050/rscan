package com.facebook.react.modules.dialog;

import android.app.AlertDialog;
import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.res.TypedArray;
import android.os.Build;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import androidx.appcompat.app.b;
import androidx.core.view.C0252a;
import androidx.core.view.V;
import androidx.fragment.app.DialogInterfaceOnCancelListenerC0293e;
import c1.AbstractC0339k;
import c1.AbstractC0341m;
import com.facebook.react.modules.dialog.DialogModule;
import d.j;
import r.v;

/* JADX INFO: loaded from: classes.dex */
public class b extends DialogInterfaceOnCancelListenerC0293e implements DialogInterface.OnClickListener {

    /* JADX INFO: renamed from: t0, reason: collision with root package name */
    private final DialogModule.b f7101t0;

    class a extends C0252a {

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        final /* synthetic */ TextView f7102d;

        a(TextView textView) {
            this.f7102d = textView;
        }

        @Override // androidx.core.view.C0252a
        public void g(View view, v vVar) {
            super.g(this.f7102d, vVar);
            vVar.x0(true);
        }
    }

    public b() {
        this.f7101t0 = null;
    }

    private static Dialog L1(Context context, Bundle bundle, DialogInterface.OnClickListener onClickListener) {
        b.a aVar = new b.a(context);
        if (bundle.containsKey("title")) {
            aVar.d(O1(context, (String) Z0.a.c(bundle.getString("title"))));
        }
        if (bundle.containsKey("button_positive")) {
            aVar.k(bundle.getString("button_positive"), onClickListener);
        }
        if (bundle.containsKey("button_negative")) {
            aVar.h(bundle.getString("button_negative"), onClickListener);
        }
        if (bundle.containsKey("button_neutral")) {
            aVar.i(bundle.getString("button_neutral"), onClickListener);
        }
        if (bundle.containsKey("message")) {
            aVar.g(bundle.getString("message"));
        }
        if (bundle.containsKey("items")) {
            aVar.f(bundle.getCharSequenceArray("items"), onClickListener);
        }
        return aVar.a();
    }

    private static Dialog M1(Context context, Bundle bundle, DialogInterface.OnClickListener onClickListener) {
        AlertDialog.Builder builder = new AlertDialog.Builder(context);
        if (bundle.containsKey("title")) {
            builder.setCustomTitle(O1(context, (String) Z0.a.c(bundle.getString("title"))));
        }
        if (bundle.containsKey("button_positive")) {
            builder.setPositiveButton(bundle.getString("button_positive"), onClickListener);
        }
        if (bundle.containsKey("button_negative")) {
            builder.setNegativeButton(bundle.getString("button_negative"), onClickListener);
        }
        if (bundle.containsKey("button_neutral")) {
            builder.setNeutralButton(bundle.getString("button_neutral"), onClickListener);
        }
        if (bundle.containsKey("message")) {
            builder.setMessage(bundle.getString("message"));
        }
        if (bundle.containsKey("items")) {
            builder.setItems(bundle.getCharSequenceArray("items"), onClickListener);
        }
        return builder.create();
    }

    public static Dialog N1(Context context, Bundle bundle, DialogInterface.OnClickListener onClickListener) {
        return P1(context) ? L1(context, bundle, onClickListener) : M1(context, bundle, onClickListener);
    }

    private static View O1(Context context, String str) {
        View viewInflate = LayoutInflater.from(context).inflate(AbstractC0341m.f5604a, (ViewGroup) null);
        TextView textView = (TextView) Z0.a.c((TextView) viewInflate.findViewById(AbstractC0339k.f5587k));
        textView.setText(str);
        textView.setFocusable(true);
        if (Build.VERSION.SDK_INT >= 28) {
            textView.setAccessibilityHeading(true);
        } else {
            V.X(textView, new a(textView));
        }
        return viewInflate;
    }

    private static boolean P1(Context context) {
        TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(j.f9139y0);
        boolean zHasValue = typedArrayObtainStyledAttributes.hasValue(j.f8958D0);
        typedArrayObtainStyledAttributes.recycle();
        return zHasValue;
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC0293e
    public Dialog E1(Bundle bundle) {
        return N1(j1(), k1(), this);
    }

    @Override // android.content.DialogInterface.OnClickListener
    public void onClick(DialogInterface dialogInterface, int i3) {
        DialogModule.b bVar = this.f7101t0;
        if (bVar != null) {
            bVar.onClick(dialogInterface, i3);
        }
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC0293e, android.content.DialogInterface.OnDismissListener
    public void onDismiss(DialogInterface dialogInterface) {
        super.onDismiss(dialogInterface);
        DialogModule.b bVar = this.f7101t0;
        if (bVar != null) {
            bVar.onDismiss(dialogInterface);
        }
    }

    public b(DialogModule.b bVar, Bundle bundle) {
        this.f7101t0 = bVar;
        r1(bundle);
    }
}
