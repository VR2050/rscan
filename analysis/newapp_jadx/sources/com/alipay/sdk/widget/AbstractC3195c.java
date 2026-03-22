package com.alipay.sdk.widget;

import android.app.Activity;
import android.widget.FrameLayout;

/* renamed from: com.alipay.sdk.widget.c */
/* loaded from: classes.dex */
public abstract class AbstractC3195c extends FrameLayout {

    /* renamed from: c */
    public static final /* synthetic */ int f8682c = 0;

    /* renamed from: e */
    public Activity f8683e;

    /* renamed from: f */
    public final String f8684f;

    public AbstractC3195c(Activity activity, String str) {
        super(activity);
        this.f8683e = activity;
        this.f8684f = str;
    }

    /* renamed from: a */
    public abstract void mo3845a();

    /* renamed from: b */
    public abstract boolean mo3846b();

    /* renamed from: c */
    public boolean m3847c() {
        return "v1".equals(this.f8684f);
    }
}
