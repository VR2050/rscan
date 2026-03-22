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
import com.jbzd.media.movecartoons.bean.response.VideoStatusBean;
import com.jbzd.media.movecartoons.p396ui.dialog.StatusPopup;
import com.jbzd.media.movecartoons.view.XDividerItemDecoration;
import com.qnmd.adnnm.da0yzo.R;
import java.util.List;
import java.util.Objects;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000(\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0007\u0018\u00002\u00020\u0001B2\u0012\u0006\u0010\r\u001a\u00020\f\u0012!\u0010\b\u001a\u001d\u0012\u0013\u0012\u00110\u0003¢\u0006\f\b\u0004\u0012\b\b\u0005\u0012\u0004\b\b(\u0006\u0012\u0004\u0012\u00020\u00070\u0002¢\u0006\u0004\b\u0011\u0010\u0012R4\u0010\b\u001a\u001d\u0012\u0013\u0012\u00110\u0003¢\u0006\f\b\u0004\u0012\b\b\u0005\u0012\u0004\b\b(\u0006\u0012\u0004\u0012\u00020\u00070\u00028\u0006@\u0006¢\u0006\f\n\u0004\b\b\u0010\t\u001a\u0004\b\n\u0010\u000bR\u0019\u0010\r\u001a\u00020\f8\u0006@\u0006¢\u0006\f\n\u0004\b\r\u0010\u000e\u001a\u0004\b\u000f\u0010\u0010¨\u0006\u0013"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/dialog/StatusPopup;", "Landroid/widget/PopupWindow;", "Lkotlin/Function1;", "Lcom/jbzd/media/movecartoons/bean/response/VideoStatusBean;", "Lkotlin/ParameterName;", "name", "order", "", "submit", "Lkotlin/jvm/functions/Function1;", "getSubmit", "()Lkotlin/jvm/functions/Function1;", "Landroid/content/Context;", "context", "Landroid/content/Context;", "getContext", "()Landroid/content/Context;", "<init>", "(Landroid/content/Context;Lkotlin/jvm/functions/Function1;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class StatusPopup extends PopupWindow {

    @NotNull
    private final Context context;

    @NotNull
    private final Function1<VideoStatusBean, Unit> submit;

    /* JADX WARN: Multi-variable type inference failed */
    public StatusPopup(@NotNull Context context, @NotNull Function1<? super VideoStatusBean, Unit> submit) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(submit, "submit");
        this.context = context;
        this.submit = submit;
        setHeight(-2);
        setWidth(-1);
        setOutsideTouchable(true);
        setFocusable(true);
        setBackgroundDrawable(new ColorDrawable(0));
        View inflate = LayoutInflater.from(context).inflate(R.layout.popup_order_by, (ViewGroup) null, false);
        setContentView(inflate);
        RecyclerView recyclerView = (RecyclerView) inflate.findViewById(R.id.f13003rv);
        recyclerView.setLayoutManager(new LinearLayoutManager(recyclerView.getContext()));
        List<VideoStatusBean> statusList = VideoStatusBean.getStatusList();
        Intrinsics.checkNotNullExpressionValue(statusList, "getStatusList()");
        StatusAdapter statusAdapter = new StatusAdapter(statusList);
        statusAdapter.setOnItemClickListener(new InterfaceC1304d() { // from class: b.a.a.a.t.e.z
            @Override // p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d
            public final void onItemClick(BaseQuickAdapter baseQuickAdapter, View view, int i2) {
                StatusPopup.m5790lambda3$lambda1$lambda0(StatusPopup.this, baseQuickAdapter, view, i2);
            }
        });
        Unit unit = Unit.INSTANCE;
        recyclerView.setAdapter(statusAdapter);
        if (recyclerView.getItemDecorationCount() == 0) {
            XDividerItemDecoration xDividerItemDecoration = new XDividerItemDecoration(recyclerView.getContext(), 1);
            xDividerItemDecoration.setDrawable(recyclerView.getResources().getDrawable(R.drawable.divider_line_order_by));
            recyclerView.addItemDecoration(xDividerItemDecoration);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: lambda-3$lambda-1$lambda-0, reason: not valid java name */
    public static final void m5790lambda3$lambda1$lambda0(StatusPopup this$0, BaseQuickAdapter adapter, View view, int i2) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
        this$0.dismiss();
        Function1<VideoStatusBean, Unit> submit = this$0.getSubmit();
        Object obj = adapter.getData().get(i2);
        Objects.requireNonNull(obj, "null cannot be cast to non-null type com.jbzd.media.movecartoons.bean.response.VideoStatusBean");
        submit.invoke((VideoStatusBean) obj);
    }

    @NotNull
    public final Context getContext() {
        return this.context;
    }

    @NotNull
    public final Function1<VideoStatusBean, Unit> getSubmit() {
        return this.submit;
    }
}
