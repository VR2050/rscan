package com.scwang.smartrefresh.layout.header;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.DashPathEffect;
import android.graphics.Paint;
import android.util.AttributeSet;
import android.view.View;
import android.widget.TextView;
import androidx.annotation.NonNull;
import com.scwang.smartrefresh.layout.R$string;
import com.scwang.smartrefresh.layout.SmartRefreshLayout;
import com.scwang.smartrefresh.layout.internal.InternalAbstract;
import p005b.p340x.p354b.p355a.p356b.InterfaceC2897f;
import p005b.p340x.p354b.p355a.p356b.InterfaceC2899h;
import p005b.p340x.p354b.p355a.p356b.InterfaceC2900i;
import p005b.p340x.p354b.p355a.p357c.EnumC2903b;
import p005b.p340x.p354b.p355a.p361g.InterpolatorC2917b;

/* loaded from: classes2.dex */
public class FalsifyHeader extends InternalAbstract implements InterfaceC2897f {

    /* renamed from: g */
    public InterfaceC2899h f10731g;

    public FalsifyHeader(Context context) {
        this(context, null);
    }

    @Override // android.view.ViewGroup, android.view.View
    public void dispatchDraw(Canvas canvas) {
        super.dispatchDraw(canvas);
        if (isInEditMode()) {
            int m3382c = InterpolatorC2917b.m3382c(5.0f);
            Context context = getContext();
            Paint paint = new Paint();
            paint.setStyle(Paint.Style.STROKE);
            paint.setColor(-858993460);
            paint.setStrokeWidth(InterpolatorC2917b.m3382c(1.0f));
            float f2 = m3382c;
            paint.setPathEffect(new DashPathEffect(new float[]{f2, f2, f2, f2}, 1.0f));
            canvas.drawRect(f2, f2, getWidth() - m3382c, getBottom() - m3382c, paint);
            TextView textView = new TextView(context);
            textView.setText(context.getString(R$string.srl_component_falsify, getClass().getSimpleName(), Float.valueOf(InterpolatorC2917b.m3387h(getHeight()))));
            textView.setTextColor(-858993460);
            textView.setGravity(17);
            textView.measure(View.MeasureSpec.makeMeasureSpec(getWidth(), 1073741824), View.MeasureSpec.makeMeasureSpec(getHeight(), 1073741824));
            textView.layout(0, 0, getWidth(), getHeight());
            textView.draw(canvas);
        }
    }

    @Override // com.scwang.smartrefresh.layout.internal.InternalAbstract, p005b.p340x.p354b.p355a.p356b.InterfaceC2898g
    /* renamed from: k */
    public void mo3355k(@NonNull InterfaceC2900i interfaceC2900i, int i2, int i3) {
        InterfaceC2899h interfaceC2899h = this.f10731g;
        if (interfaceC2899h != null) {
            ((SmartRefreshLayout.C4087m) interfaceC2899h).m4627d(EnumC2903b.None);
            ((SmartRefreshLayout.C4087m) this.f10731g).m4627d(EnumC2903b.RefreshFinish);
        }
    }

    @Override // com.scwang.smartrefresh.layout.internal.InternalAbstract, p005b.p340x.p354b.p355a.p356b.InterfaceC2898g
    /* renamed from: o */
    public void mo3356o(@NonNull InterfaceC2899h interfaceC2899h, int i2, int i3) {
        this.f10731g = interfaceC2899h;
    }

    public FalsifyHeader(Context context, AttributeSet attributeSet) {
        super(context, attributeSet, 0);
    }
}
