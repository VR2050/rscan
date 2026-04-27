package com.facebook.react.views.unimplementedview;

import android.content.Context;
import android.widget.LinearLayout;
import androidx.appcompat.widget.D;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class a extends LinearLayout {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final D f8282b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(Context context) {
        super(context);
        j.f(context, "context");
        D d3 = new D(context);
        this.f8282b = d3;
        d3.setLayoutParams(new LinearLayout.LayoutParams(-2, -1));
        d3.setGravity(17);
        d3.setTextColor(-1);
        setBackgroundColor(1442775040);
        setGravity(1);
        setOrientation(1);
        addView(d3);
    }

    public final void setName$ReactAndroid_release(String str) {
        j.f(str, "name");
        this.f8282b.setText("'" + str + "' is not Fabric compatible yet.");
    }
}
