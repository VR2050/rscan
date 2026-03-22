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
import com.jbzd.media.movecartoons.p396ui.dialog.OptionPopup;
import com.qnmd.adnnm.da0yzo.R;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.CollectionsKt___CollectionsKt;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p009a.C0859m0;
import p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u00000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010 \n\u0002\b\b\u0018\u0000 \u00182\u00020\u0001:\u0001\u0018BD\u0012\u0006\u0010\r\u001a\u00020\f\u0012\u0010\b\u0002\u0010\u0012\u001a\n\u0012\u0004\u0012\u00020\u0003\u0018\u00010\u0011\u0012!\u0010\b\u001a\u001d\u0012\u0013\u0012\u00110\u0003¢\u0006\f\b\u0004\u0012\b\b\u0005\u0012\u0004\b\b(\u0006\u0012\u0004\u0012\u00020\u00070\u0002¢\u0006\u0004\b\u0016\u0010\u0017R4\u0010\b\u001a\u001d\u0012\u0013\u0012\u00110\u0003¢\u0006\f\b\u0004\u0012\b\b\u0005\u0012\u0004\b\b(\u0006\u0012\u0004\u0012\u00020\u00070\u00028\u0006@\u0006¢\u0006\f\n\u0004\b\b\u0010\t\u001a\u0004\b\n\u0010\u000bR\u0019\u0010\r\u001a\u00020\f8\u0006@\u0006¢\u0006\f\n\u0004\b\r\u0010\u000e\u001a\u0004\b\u000f\u0010\u0010R!\u0010\u0012\u001a\n\u0012\u0004\u0012\u00020\u0003\u0018\u00010\u00118\u0006@\u0006¢\u0006\f\n\u0004\b\u0012\u0010\u0013\u001a\u0004\b\u0014\u0010\u0015¨\u0006\u0019"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/dialog/OptionPopup;", "Landroid/widget/PopupWindow;", "Lkotlin/Function1;", "", "Lkotlin/ParameterName;", "name", "item", "", "submit", "Lkotlin/jvm/functions/Function1;", "getSubmit", "()Lkotlin/jvm/functions/Function1;", "Landroid/content/Context;", "context", "Landroid/content/Context;", "getContext", "()Landroid/content/Context;", "", "list", "Ljava/util/List;", "getList", "()Ljava/util/List;", "<init>", "(Landroid/content/Context;Ljava/util/List;Lkotlin/jvm/functions/Function1;)V", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class OptionPopup extends PopupWindow {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @NotNull
    private final Context context;

    @Nullable
    private final List<String> list;

    @NotNull
    private final Function1<String, Unit> submit;

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000:\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010 \n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0006\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0014\u0010\u0015JH\u0010\u000e\u001a\u00020\r2\u0006\u0010\u0003\u001a\u00020\u00022\u000e\u0010\u0006\u001a\n\u0012\u0004\u0012\u00020\u0005\u0018\u00010\u00042!\u0010\f\u001a\u001d\u0012\u0013\u0012\u00110\u0005¢\u0006\f\b\b\u0012\b\b\t\u0012\u0004\b\b(\n\u0012\u0004\u0012\u00020\u000b0\u0007¢\u0006\u0004\b\u000e\u0010\u000fJH\u0010\u0012\u001a\u00020\u000b2\u0006\u0010\u0011\u001a\u00020\u00102\u000e\u0010\u0006\u001a\n\u0012\u0004\u0012\u00020\u0005\u0018\u00010\u00042!\u0010\f\u001a\u001d\u0012\u0013\u0012\u00110\u0005¢\u0006\f\b\b\u0012\b\b\t\u0012\u0004\b\b(\n\u0012\u0004\u0012\u00020\u000b0\u0007¢\u0006\u0004\b\u0012\u0010\u0013¨\u0006\u0016"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/dialog/OptionPopup$Companion;", "", "Landroid/content/Context;", "context", "", "", "list", "Lkotlin/Function1;", "Lkotlin/ParameterName;", "name", "item", "", "submit", "Lcom/jbzd/media/movecartoons/ui/dialog/OptionPopup;", "getOptionPopup", "(Landroid/content/Context;Ljava/util/List;Lkotlin/jvm/functions/Function1;)Lcom/jbzd/media/movecartoons/ui/dialog/OptionPopup;", "Landroid/view/View;", "view", "showOptionPopup", "(Landroid/view/View;Ljava/util/List;Lkotlin/jvm/functions/Function1;)V", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final OptionPopup getOptionPopup(@NotNull Context context, @Nullable List<String> list, @NotNull Function1<? super String, Unit> submit) {
            Intrinsics.checkNotNullParameter(context, "context");
            Intrinsics.checkNotNullParameter(submit, "submit");
            return new OptionPopup(context, list, submit);
        }

        public final void showOptionPopup(@NotNull View view, @Nullable List<String> list, @NotNull Function1<? super String, Unit> submit) {
            Intrinsics.checkNotNullParameter(view, "view");
            Intrinsics.checkNotNullParameter(submit, "submit");
            Context context = view.getContext();
            Intrinsics.checkNotNullExpressionValue(context, "view.context");
            getOptionPopup(context, list, submit).showAsDropDown(view);
        }
    }

    public /* synthetic */ OptionPopup(Context context, List list, Function1 function1, int i2, DefaultConstructorMarker defaultConstructorMarker) {
        this(context, (i2 & 2) != 0 ? null : list, function1);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: lambda-2$lambda-1$lambda-0, reason: not valid java name */
    public static final void m5778lambda2$lambda1$lambda0(OptionPopup this$0, BaseQuickAdapter adapter, View view, int i2) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
        this$0.dismiss();
        Function1<String, Unit> submit = this$0.getSubmit();
        Object obj = adapter.getData().get(i2);
        Objects.requireNonNull(obj, "null cannot be cast to non-null type kotlin.String");
        submit.invoke((String) obj);
    }

    @NotNull
    public final Context getContext() {
        return this.context;
    }

    @Nullable
    public final List<String> getList() {
        return this.list;
    }

    @NotNull
    public final Function1<String, Unit> getSubmit() {
        return this.submit;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public OptionPopup(@NotNull Context context, @Nullable List<String> list, @NotNull Function1<? super String, Unit> submit) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(submit, "submit");
        this.context = context;
        this.list = list;
        this.submit = submit;
        setHeight(-2);
        setWidth(C2354n.m2425R(context, 75.0f));
        setOutsideTouchable(true);
        setFocusable(true);
        setBackgroundDrawable(new ColorDrawable(0));
        View inflate = LayoutInflater.from(context).inflate(R.layout.popup_order_by, (ViewGroup) null, false);
        setContentView(inflate);
        RecyclerView view = (RecyclerView) inflate.findViewById(R.id.f13003rv);
        view.setLayoutManager(new LinearLayoutManager(view.getContext()));
        List<String> list2 = getList();
        OptionAdapter optionAdapter = new OptionAdapter(list2 != null ? CollectionsKt___CollectionsKt.toMutableList((Collection) list2) : null);
        optionAdapter.setOnItemClickListener(new InterfaceC1304d() { // from class: b.a.a.a.t.e.n
            @Override // p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d
            public final void onItemClick(BaseQuickAdapter baseQuickAdapter, View view2, int i2) {
                OptionPopup.m5778lambda2$lambda1$lambda0(OptionPopup.this, baseQuickAdapter, view2, i2);
            }
        });
        Unit unit = Unit.INSTANCE;
        view.setAdapter(optionAdapter);
        Intrinsics.checkNotNullExpressionValue(view, "rv");
        Intrinsics.checkNotNullParameter(view, "view");
        view.setOutlineProvider(new C0859m0(1.5d));
        view.setClipToOutline(true);
    }
}
