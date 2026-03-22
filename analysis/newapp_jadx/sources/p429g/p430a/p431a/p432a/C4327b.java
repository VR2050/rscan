package p429g.p430a.p431a.p432a;

import android.view.View;
import io.github.armcha.autolink.AutoLinkTextView;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* renamed from: g.a.a.a.b */
/* loaded from: classes2.dex */
public final class C4327b extends AbstractC4333h {

    /* renamed from: g */
    public final /* synthetic */ AutoLinkTextView f11177g;

    /* renamed from: h */
    public final /* synthetic */ C4326a f11178h;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4327b(AutoLinkTextView autoLinkTextView, C4326a c4326a, int i2, int i3, int i4) {
        super(i3, i4);
        this.f11177g = autoLinkTextView;
        this.f11178h = c4326a;
    }

    @Override // android.text.style.ClickableSpan
    public void onClick(@NotNull View widget) {
        Intrinsics.checkNotNullParameter(widget, "widget");
        Function1<? super C4326a, Unit> function1 = this.f11177g.onAutoLinkClick;
        if (function1 != null) {
            function1.invoke(this.f11178h);
        }
    }
}
