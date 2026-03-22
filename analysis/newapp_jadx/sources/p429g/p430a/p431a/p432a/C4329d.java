package p429g.p430a.p431a.p432a;

import android.text.Layout;
import android.text.Selection;
import android.text.Spannable;
import android.text.method.LinkMovementMethod;
import android.view.MotionEvent;
import android.widget.TextView;
import kotlin.collections.ArraysKt___ArraysKt;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* renamed from: g.a.a.a.d */
/* loaded from: classes2.dex */
public final class C4329d extends LinkMovementMethod {

    /* renamed from: a */
    public AbstractC4333h f11179a;

    /* renamed from: a */
    public final AbstractC4333h m4907a(TextView textView, Spannable spannable, MotionEvent motionEvent) {
        int x = (int) motionEvent.getX();
        int y = (int) motionEvent.getY();
        int totalPaddingLeft = x - textView.getTotalPaddingLeft();
        int totalPaddingTop = y - textView.getTotalPaddingTop();
        int scrollX = textView.getScrollX() + totalPaddingLeft;
        int scrollY = textView.getScrollY() + totalPaddingTop;
        Layout layout = textView.getLayout();
        int offsetForHorizontal = layout.getOffsetForHorizontal(layout.getLineForVertical(scrollY), scrollX);
        AbstractC4333h[] link = (AbstractC4333h[]) spannable.getSpans(offsetForHorizontal, offsetForHorizontal, AbstractC4333h.class);
        Intrinsics.checkNotNullExpressionValue(link, "link");
        return (AbstractC4333h) ArraysKt___ArraysKt.getOrNull(link, 0);
    }

    @Override // android.text.method.LinkMovementMethod, android.text.method.ScrollingMovementMethod, android.text.method.BaseMovementMethod, android.text.method.MovementMethod
    public boolean onTouchEvent(@NotNull TextView textView, @NotNull Spannable spannable, @NotNull MotionEvent event) {
        Intrinsics.checkNotNullParameter(textView, "textView");
        Intrinsics.checkNotNullParameter(spannable, "spannable");
        Intrinsics.checkNotNullParameter(event, "event");
        int action = event.getAction();
        if (action == 0) {
            AbstractC4333h m4907a = m4907a(textView, spannable, event);
            this.f11179a = m4907a;
            if (m4907a != null) {
                if (m4907a != null) {
                    m4907a.f11186c = true;
                }
                Selection.setSelection(spannable, spannable.getSpanStart(m4907a), spannable.getSpanEnd(this.f11179a));
            }
        } else if (action != 2) {
            AbstractC4333h abstractC4333h = this.f11179a;
            if (abstractC4333h != null) {
                if (abstractC4333h != null) {
                    abstractC4333h.f11186c = false;
                }
                super.onTouchEvent(textView, spannable, event);
            }
            this.f11179a = null;
            Selection.removeSelection(spannable);
        } else {
            AbstractC4333h m4907a2 = m4907a(textView, spannable, event);
            if (this.f11179a != null && (!Intrinsics.areEqual(m4907a2, r8))) {
                AbstractC4333h abstractC4333h2 = this.f11179a;
                if (abstractC4333h2 != null) {
                    abstractC4333h2.f11186c = false;
                }
                this.f11179a = null;
                Selection.removeSelection(spannable);
            }
        }
        return true;
    }
}
