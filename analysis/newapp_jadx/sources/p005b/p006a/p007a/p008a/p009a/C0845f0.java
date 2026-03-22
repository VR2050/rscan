package p005b.p006a.p007a.p008a.p009a;

import android.content.SharedPreferences;
import android.graphics.Color;
import android.text.TextPaint;
import android.text.style.ClickableSpan;
import android.view.View;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p005b.p327w.p330b.C2827a;
import p005b.p327w.p330b.p331b.ApplicationC2828a;

/* renamed from: b.a.a.a.a.f0 */
/* loaded from: classes2.dex */
public final class C0845f0<T> extends ClickableSpan {

    /* renamed from: c */
    public final T f246c;

    /* renamed from: e */
    @NotNull
    public final Function1<T, Unit> f247e;

    /* JADX WARN: Multi-variable type inference failed */
    public C0845f0(T t, @NotNull Function1<? super T, Unit> click) {
        Intrinsics.checkNotNullParameter(click, "click");
        this.f246c = t;
        this.f247e = click;
    }

    @Override // android.text.style.ClickableSpan
    public void onClick(@NotNull View view) {
        Intrinsics.checkNotNullParameter(view, "view");
        this.f247e.invoke(this.f246c);
    }

    @Override // android.text.style.ClickableSpan, android.text.style.CharacterStyle
    public void updateDrawState(@NotNull TextPaint ds) {
        Intrinsics.checkNotNullParameter(ds, "ds");
        super.updateDrawState(ds);
        Intrinsics.checkNotNullParameter("MY_THEME_KEY", "key");
        ApplicationC2828a applicationC2828a = C2827a.f7670a;
        if (applicationC2828a == null) {
            Intrinsics.throwUninitializedPropertyAccessException("context");
            throw null;
        }
        SharedPreferences sharedPreferences = applicationC2828a.getSharedPreferences("default_storage", 0);
        Intrinsics.checkNotNullExpressionValue(sharedPreferences, "SupportLibraryInstance.context.getSharedPreferences(DEFAULT_STORAGE_NAME,Context.MODE_PRIVATE)");
        sharedPreferences.getBoolean("MY_THEME_KEY", false);
        ds.setColor(Color.argb(255, 255, 0, 0));
        ds.setUnderlineText(false);
    }
}
