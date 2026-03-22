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
import com.jbzd.media.movecartoons.bean.response.PostIndexBean;
import com.jbzd.media.movecartoons.p396ui.dialog.PostsPopup;
import com.qnmd.adnnm.da0yzo.R;
import java.util.List;
import java.util.Objects;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.TypeIntrinsics;
import org.jetbrains.annotations.NotNull;
import p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u00000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0007\u0018\u00002\u00020\u0001B@\u0012\u0006\u0010\u0003\u001a\u00020\u0002\u0012\f\u0010\t\u001a\b\u0012\u0004\u0012\u00020\b0\u0007\u0012!\u0010\u0012\u001a\u001d\u0012\u0013\u0012\u00110\b¢\u0006\f\b\u000e\u0012\b\b\u000f\u0012\u0004\b\b(\u0010\u0012\u0004\u0012\u00020\u00110\r¢\u0006\u0004\b\u0016\u0010\u0017R\u0019\u0010\u0003\u001a\u00020\u00028\u0006@\u0006¢\u0006\f\n\u0004\b\u0003\u0010\u0004\u001a\u0004\b\u0005\u0010\u0006R\u001f\u0010\t\u001a\b\u0012\u0004\u0012\u00020\b0\u00078\u0006@\u0006¢\u0006\f\n\u0004\b\t\u0010\n\u001a\u0004\b\u000b\u0010\fR4\u0010\u0012\u001a\u001d\u0012\u0013\u0012\u00110\b¢\u0006\f\b\u000e\u0012\b\b\u000f\u0012\u0004\b\b(\u0010\u0012\u0004\u0012\u00020\u00110\r8\u0006@\u0006¢\u0006\f\n\u0004\b\u0012\u0010\u0013\u001a\u0004\b\u0014\u0010\u0015¨\u0006\u0018"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/dialog/PostsPopup;", "Landroid/widget/PopupWindow;", "Landroid/content/Context;", "context", "Landroid/content/Context;", "getContext", "()Landroid/content/Context;", "", "Lcom/jbzd/media/movecartoons/bean/response/PostIndexBean$Types;", "list", "Ljava/util/List;", "getList", "()Ljava/util/List;", "Lkotlin/Function1;", "Lkotlin/ParameterName;", "name", "type", "", "submit", "Lkotlin/jvm/functions/Function1;", "getSubmit", "()Lkotlin/jvm/functions/Function1;", "<init>", "(Landroid/content/Context;Ljava/util/List;Lkotlin/jvm/functions/Function1;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class PostsPopup extends PopupWindow {

    @NotNull
    private final Context context;

    @NotNull
    private final List<PostIndexBean.Types> list;

    @NotNull
    private final Function1<PostIndexBean.Types, Unit> submit;

    /* JADX WARN: Multi-variable type inference failed */
    public PostsPopup(@NotNull Context context, @NotNull List<? extends PostIndexBean.Types> list, @NotNull Function1<? super PostIndexBean.Types, Unit> submit) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(list, "list");
        Intrinsics.checkNotNullParameter(submit, "submit");
        this.context = context;
        this.list = list;
        this.submit = submit;
        setHeight(-2);
        setWidth(-2);
        setOutsideTouchable(true);
        setFocusable(true);
        setBackgroundDrawable(new ColorDrawable(0));
        View inflate = LayoutInflater.from(context).inflate(R.layout.popup_menu, (ViewGroup) null, false);
        RecyclerView recyclerView = (RecyclerView) inflate.findViewById(R.id.f13003rv);
        recyclerView.setLayoutManager(new LinearLayoutManager(recyclerView.getContext()));
        PopupAdapter popupAdapter = new PopupAdapter(TypeIntrinsics.asMutableList(getList()));
        popupAdapter.setOnItemClickListener(new InterfaceC1304d() { // from class: b.a.a.a.t.e.r
            @Override // p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d
            public final void onItemClick(BaseQuickAdapter baseQuickAdapter, View view, int i2) {
                PostsPopup.m5782lambda2$lambda1$lambda0(PostsPopup.this, baseQuickAdapter, view, i2);
            }
        });
        Unit unit = Unit.INSTANCE;
        recyclerView.setAdapter(popupAdapter);
        setContentView(inflate);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: lambda-2$lambda-1$lambda-0, reason: not valid java name */
    public static final void m5782lambda2$lambda1$lambda0(PostsPopup this$0, BaseQuickAdapter adapter, View view, int i2) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
        this$0.dismiss();
        Function1<PostIndexBean.Types, Unit> submit = this$0.getSubmit();
        Object item = adapter.getItem(i2);
        Objects.requireNonNull(item, "null cannot be cast to non-null type @[ParameterName(name = 'type')] com.jbzd.media.movecartoons.bean.response.PostIndexBean.Types");
        submit.invoke((PostIndexBean.Types) item);
    }

    @NotNull
    public final Context getContext() {
        return this.context;
    }

    @NotNull
    public final List<PostIndexBean.Types> getList() {
        return this.list;
    }

    @NotNull
    public final Function1<PostIndexBean.Types, Unit> getSubmit() {
        return this.submit;
    }
}
