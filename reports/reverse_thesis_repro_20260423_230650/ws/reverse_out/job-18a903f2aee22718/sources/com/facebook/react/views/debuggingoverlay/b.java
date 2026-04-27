package com.facebook.react.views.debuggingoverlay;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.RectF;
import android.view.View;
import com.facebook.react.bridge.UiThreadUtil;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class b extends View {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final Paint f7776b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final HashMap f7777c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final HashMap f7778d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final Paint f7779e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private List f7780f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(Context context) {
        super(context);
        j.f(context, "context");
        Paint paint = new Paint();
        this.f7776b = paint;
        this.f7777c = new HashMap();
        this.f7778d = new HashMap();
        Paint paint2 = new Paint();
        this.f7779e = paint2;
        this.f7780f = new ArrayList();
        paint.setStyle(Paint.Style.STROKE);
        paint.setStrokeWidth(6.0f);
        paint2.setStyle(Paint.Style.FILL);
        paint2.setColor(-859248897);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void c(b bVar, int i3) {
        bVar.f7777c.remove(Integer.valueOf(i3));
        bVar.f7778d.remove(Integer.valueOf(i3));
        bVar.invalidate();
    }

    public final void b() {
        this.f7780f.clear();
        invalidate();
    }

    @Override // android.view.View
    protected void onDraw(Canvas canvas) {
        j.f(canvas, "canvas");
        super.onDraw(canvas);
        for (Object obj : this.f7777c.values()) {
            j.e(obj, "next(...)");
            c cVar = (c) obj;
            this.f7776b.setColor(cVar.a());
            canvas.drawRect(cVar.c(), this.f7776b);
            final int iB = cVar.b();
            Runnable runnable = new Runnable() { // from class: com.facebook.react.views.debuggingoverlay.a
                @Override // java.lang.Runnable
                public final void run() {
                    b.c(this.f7774b, iB);
                }
            };
            if (!this.f7778d.containsKey(Integer.valueOf(iB))) {
                this.f7778d.put(Integer.valueOf(iB), runnable);
                UiThreadUtil.runOnUiThread(runnable, 2000L);
            }
        }
        Iterator it = this.f7780f.iterator();
        while (it.hasNext()) {
            canvas.drawRect((RectF) it.next(), this.f7779e);
        }
    }

    public final void setHighlightedElementsRectangles(List<RectF> list) {
        j.f(list, "elementsRectangles");
        this.f7780f = list;
        invalidate();
    }

    public final void setTraceUpdates(List<c> list) {
        j.f(list, "traceUpdates");
        for (c cVar : list) {
            int iB = cVar.b();
            if (this.f7778d.containsKey(Integer.valueOf(iB))) {
                UiThreadUtil.removeOnUiThread((Runnable) this.f7778d.get(Integer.valueOf(iB)));
                this.f7778d.remove(Integer.valueOf(iB));
            }
            this.f7777c.put(Integer.valueOf(iB), cVar);
        }
        invalidate();
    }
}
