package Y1;

import android.content.Context;
import android.text.TextPaint;
import android.text.style.ClickableSpan;
import android.view.View;
import com.facebook.react.bridge.ReactContext;
import com.facebook.react.uimanager.H0;
import com.facebook.react.uimanager.events.EventDispatcher;

/* JADX INFO: loaded from: classes.dex */
public final class f extends ClickableSpan implements i {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final int f2887a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private boolean f2888b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private int f2889c;

    public f(int i3) {
        this.f2887a = i3;
    }

    public final void a(int i3) {
        this.f2889c = i3;
    }

    public final void b(boolean z3) {
        this.f2888b = z3;
    }

    @Override // android.text.style.ClickableSpan
    public void onClick(View view) {
        t2.j.f(view, "view");
        Context context = view.getContext();
        t2.j.d(context, "null cannot be cast to non-null type com.facebook.react.bridge.ReactContext");
        ReactContext reactContext = (ReactContext) context;
        EventDispatcher eventDispatcherC = H0.c(reactContext, this.f2887a);
        if (eventDispatcherC != null) {
            eventDispatcherC.g(new com.facebook.react.views.view.j(H0.e(reactContext), this.f2887a));
        }
    }

    @Override // android.text.style.ClickableSpan, android.text.style.CharacterStyle
    public void updateDrawState(TextPaint textPaint) {
        t2.j.f(textPaint, "ds");
        if (this.f2888b) {
            textPaint.bgColor = this.f2889c;
        }
    }
}
