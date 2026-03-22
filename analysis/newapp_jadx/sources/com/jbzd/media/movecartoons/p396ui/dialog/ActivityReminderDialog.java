package com.jbzd.media.movecartoons.p396ui.dialog;

import android.app.Dialog;
import android.content.Context;
import android.graphics.Color;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import android.widget.ImageView;
import com.jbzd.media.movecartoons.p396ui.dialog.ActivityReminderDialog;
import com.qnmd.adnnm.da0yzo.R;
import p005b.p143g.p144a.ComponentCallbacks2C1553c;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* loaded from: classes2.dex */
public class ActivityReminderDialog extends Dialog {
    private Context context;
    public ImageView iv_cancel;
    public ImageView iv_promotional_graphics;
    private View.OnClickListener mClickListener;

    public ActivityReminderDialog(Context context) {
        this(context, R.style.TopScaleDialogStyle);
        this.context = context;
    }

    /* renamed from: a */
    public /* synthetic */ void m4241a(View view) {
        View.OnClickListener onClickListener = this.mClickListener;
        if (onClickListener != null) {
            onClickListener.onClick(this.iv_promotional_graphics);
        }
    }

    public void init() {
        View inflate = LayoutInflater.from(this.context).inflate(R.layout.dialog_activity_reminder, (ViewGroup) null);
        setContentView(inflate);
        this.iv_promotional_graphics = (ImageView) inflate.findViewById(R.id.iv_promotional_graphics);
        this.iv_cancel = (ImageView) inflate.findViewById(R.id.iv_cancel);
        this.iv_promotional_graphics.setOnClickListener(new View.OnClickListener() { // from class: b.a.a.a.t.e.b
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                ActivityReminderDialog.this.m4241a(view);
            }
        });
        this.iv_cancel.setOnClickListener(new View.OnClickListener() { // from class: b.a.a.a.t.e.a
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                ActivityReminderDialog.this.dismiss();
            }
        });
        Window window = getWindow();
        if (window != null) {
            window.getDecorView().setPadding(C4195m.m4785R(30.0f), 0, C4195m.m4785R(30.0f), 0);
            WindowManager.LayoutParams attributes = window.getAttributes();
            attributes.width = -1;
            window.setAttributes(attributes);
            window.getDecorView().setBackgroundColor(Color.argb(0, 0, 0, 0));
            window.setGravity(17);
        }
    }

    @Override // android.app.Dialog
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        requestWindowFeature(1);
        init();
    }

    public void setClicklistener(View.OnClickListener onClickListener) {
        this.mClickListener = onClickListener;
    }

    public void setImage(Drawable drawable) {
        if (this.iv_promotional_graphics != null) {
            ComponentCallbacks2C1553c.m738h(this.context).mo773f(drawable).m757R(this.iv_promotional_graphics);
        }
    }

    public ActivityReminderDialog(Context context, int i2) {
        super(context, R.style.TopScaleDialogStyle);
        this.context = context;
    }
}
