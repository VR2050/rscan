package com.jbzd.media.movecartoons.p396ui.dialog;

import android.content.Context;
import android.graphics.drawable.ColorDrawable;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.PopupWindow;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.jbzd.media.movecartoons.p396ui.dialog.OrderByPopup;
import com.qnmd.adnnm.da0yzo.R;
import java.util.Objects;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p009a.C0834a;
import p005b.p006a.p007a.p008a.p009a.C0835a0;
import p005b.p006a.p007a.p008a.p009a.C0859m0;
import p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u00002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0007\u0018\u00002\u00020\u0001B2\u0012\u0006\u0010\u0013\u001a\u00020\u0012\u0012!\u0010\u000b\u001a\u001d\u0012\u0013\u0012\u00110\u0002¢\u0006\f\b\b\u0012\b\b\t\u0012\u0004\b\b(\n\u0012\u0004\u0012\u00020\u00040\u0007¢\u0006\u0004\b\u0017\u0010\u0018J\u0017\u0010\u0005\u001a\u00020\u00042\b\u0010\u0003\u001a\u0004\u0018\u00010\u0002¢\u0006\u0004\b\u0005\u0010\u0006R4\u0010\u000b\u001a\u001d\u0012\u0013\u0012\u00110\u0002¢\u0006\f\b\b\u0012\b\b\t\u0012\u0004\b\b(\n\u0012\u0004\u0012\u00020\u00040\u00078\u0006@\u0006¢\u0006\f\n\u0004\b\u000b\u0010\f\u001a\u0004\b\r\u0010\u000eR\u0016\u0010\u0010\u001a\u00020\u000f8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u0010\u0010\u0011R\u0019\u0010\u0013\u001a\u00020\u00128\u0006@\u0006¢\u0006\f\n\u0004\b\u0013\u0010\u0014\u001a\u0004\b\u0015\u0010\u0016¨\u0006\u0019"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/dialog/OrderByPopup;", "Landroid/widget/PopupWindow;", "Lb/a/a/a/a/a0;", "curOrderBy", "", "updateCurOrderBy", "(Lb/a/a/a/a/a0;)V", "Lkotlin/Function1;", "Lkotlin/ParameterName;", "name", "order", "submit", "Lkotlin/jvm/functions/Function1;", "getSubmit", "()Lkotlin/jvm/functions/Function1;", "Lcom/jbzd/media/movecartoons/ui/dialog/OrderAdapter;", "menuAdapter", "Lcom/jbzd/media/movecartoons/ui/dialog/OrderAdapter;", "Landroid/content/Context;", "context", "Landroid/content/Context;", "getContext", "()Landroid/content/Context;", "<init>", "(Landroid/content/Context;Lkotlin/jvm/functions/Function1;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class OrderByPopup extends PopupWindow {

    @NotNull
    private final Context context;

    @NotNull
    private OrderAdapter menuAdapter;

    @NotNull
    private final Function1<C0835a0, Unit> submit;

    /* JADX WARN: Multi-variable type inference failed */
    public OrderByPopup(@NotNull Context context, @NotNull Function1<? super C0835a0, Unit> submit) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(submit, "submit");
        this.context = context;
        this.submit = submit;
        C0834a c0834a = C0834a.f214a;
        OrderAdapter orderAdapter = new OrderAdapter(C0834a.m173a());
        orderAdapter.setOnItemClickListener(new InterfaceC1304d() { // from class: b.a.a.a.t.e.o
            @Override // p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d
            public final void onItemClick(BaseQuickAdapter baseQuickAdapter, View view, int i2) {
                OrderByPopup.m5779menuAdapter$lambda1$lambda0(OrderByPopup.this, baseQuickAdapter, view, i2);
            }
        });
        Unit unit = Unit.INSTANCE;
        this.menuAdapter = orderAdapter;
        setHeight(-2);
        setWidth(C2354n.m2425R(context, 75.0f));
        setOutsideTouchable(true);
        setFocusable(true);
        setBackgroundDrawable(new ColorDrawable(0));
        View inflate = LayoutInflater.from(context).inflate(R.layout.popup_order_by, (ViewGroup) null, false);
        setContentView(inflate);
        RecyclerView view = (RecyclerView) inflate.findViewById(R.id.f13003rv);
        view.setLayoutManager(new LinearLayoutManager(view.getContext()));
        view.setAdapter(this.menuAdapter);
        Intrinsics.checkNotNullExpressionValue(view, "rv");
        Intrinsics.checkNotNullParameter(view, "view");
        view.setOutlineProvider(new C0859m0(1.5d));
        view.setClipToOutline(true);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: menuAdapter$lambda-1$lambda-0, reason: not valid java name */
    public static final void m5779menuAdapter$lambda1$lambda0(OrderByPopup this$0, BaseQuickAdapter adapter, View view, int i2) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
        this$0.dismiss();
        Function1<C0835a0, Unit> submit = this$0.getSubmit();
        Object obj = adapter.getData().get(i2);
        Objects.requireNonNull(obj, "null cannot be cast to non-null type com.jbzd.media.movecartoons.utils.OrderByBean");
        submit.invoke((C0835a0) obj);
    }

    @NotNull
    public final Context getContext() {
        return this.context;
    }

    @NotNull
    public final Function1<C0835a0, Unit> getSubmit() {
        return this.submit;
    }

    public final void updateCurOrderBy(@Nullable C0835a0 curOrderBy) {
        this.menuAdapter.updateCur(curOrderBy);
    }
}
