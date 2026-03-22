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
import com.jbzd.media.movecartoons.bean.response.VideoTypeBean;
import com.jbzd.media.movecartoons.p396ui.dialog.VideoTypePopup;
import com.qnmd.adnnm.da0yzo.R;
import java.util.ArrayList;
import java.util.Objects;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.CollectionsKt__CollectionsKt;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p009a.C0859m0;
import p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000>\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0005\u0018\u00002\u00020\u0001B2\u0012\u0006\u0010\f\u001a\u00020\u000b\u0012!\u0010\u0014\u001a\u001d\u0012\u0013\u0012\u00110\u0002¢\u0006\f\b\u0011\u0012\b\b\u0012\u0012\u0004\b\b(\u0013\u0012\u0004\u0012\u00020\u00040\u0010¢\u0006\u0004\b\u001b\u0010\u001cJ\u0017\u0010\u0005\u001a\u00020\u00042\b\u0010\u0003\u001a\u0004\u0018\u00010\u0002¢\u0006\u0004\b\u0005\u0010\u0006R&\u0010\t\u001a\u0012\u0012\u0004\u0012\u00020\u00020\u0007j\b\u0012\u0004\u0012\u00020\u0002`\b8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b\t\u0010\nR\u0019\u0010\f\u001a\u00020\u000b8\u0006@\u0006¢\u0006\f\n\u0004\b\f\u0010\r\u001a\u0004\b\u000e\u0010\u000fR4\u0010\u0014\u001a\u001d\u0012\u0013\u0012\u00110\u0002¢\u0006\f\b\u0011\u0012\b\b\u0012\u0012\u0004\b\b(\u0013\u0012\u0004\u0012\u00020\u00040\u00108\u0006@\u0006¢\u0006\f\n\u0004\b\u0014\u0010\u0015\u001a\u0004\b\u0016\u0010\u0017R\u0016\u0010\u0019\u001a\u00020\u00188\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u0019\u0010\u001a¨\u0006\u001d"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/dialog/VideoTypePopup;", "Landroid/widget/PopupWindow;", "Lcom/jbzd/media/movecartoons/bean/response/VideoTypeBean;", "curType", "", "updateCurType", "(Lcom/jbzd/media/movecartoons/bean/response/VideoTypeBean;)V", "Ljava/util/ArrayList;", "Lkotlin/collections/ArrayList;", "videoTypeList", "Ljava/util/ArrayList;", "Landroid/content/Context;", "context", "Landroid/content/Context;", "getContext", "()Landroid/content/Context;", "Lkotlin/Function1;", "Lkotlin/ParameterName;", "name", "type", "submit", "Lkotlin/jvm/functions/Function1;", "getSubmit", "()Lkotlin/jvm/functions/Function1;", "Lcom/jbzd/media/movecartoons/ui/dialog/TypeAdapter;", "menuAdapter", "Lcom/jbzd/media/movecartoons/ui/dialog/TypeAdapter;", "<init>", "(Landroid/content/Context;Lkotlin/jvm/functions/Function1;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class VideoTypePopup extends PopupWindow {

    @NotNull
    private final Context context;

    @NotNull
    private TypeAdapter menuAdapter;

    @NotNull
    private final Function1<VideoTypeBean, Unit> submit;

    @NotNull
    private final ArrayList<VideoTypeBean> videoTypeList;

    /* JADX WARN: Multi-variable type inference failed */
    public VideoTypePopup(@NotNull Context context, @NotNull Function1<? super VideoTypeBean, Unit> submit) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(submit, "submit");
        this.context = context;
        this.submit = submit;
        ArrayList<VideoTypeBean> arrayListOf = CollectionsKt__CollectionsKt.arrayListOf(new VideoTypeBean("", context.getString(R.string.video_type_all)), new VideoTypeBean(VideoTypeBean.video_type_vip, context.getString(R.string.video_type_vip)), new VideoTypeBean(VideoTypeBean.video_type_point, context.getString(R.string.video_type_point)), new VideoTypeBean(VideoTypeBean.video_type_free, context.getString(R.string.video_type_free)));
        this.videoTypeList = arrayListOf;
        TypeAdapter typeAdapter = new TypeAdapter(arrayListOf);
        typeAdapter.setOnItemClickListener(new InterfaceC1304d() { // from class: b.a.a.a.t.e.h0
            @Override // p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d
            public final void onItemClick(BaseQuickAdapter baseQuickAdapter, View view, int i2) {
                VideoTypePopup.m5798menuAdapter$lambda1$lambda0(VideoTypePopup.this, baseQuickAdapter, view, i2);
            }
        });
        Unit unit = Unit.INSTANCE;
        this.menuAdapter = typeAdapter;
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
    public static final void m5798menuAdapter$lambda1$lambda0(VideoTypePopup this$0, BaseQuickAdapter adapter, View view, int i2) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
        this$0.dismiss();
        Function1<VideoTypeBean, Unit> submit = this$0.getSubmit();
        Object obj = adapter.getData().get(i2);
        Objects.requireNonNull(obj, "null cannot be cast to non-null type com.jbzd.media.movecartoons.bean.response.VideoTypeBean");
        submit.invoke((VideoTypeBean) obj);
    }

    @NotNull
    public final Context getContext() {
        return this.context;
    }

    @NotNull
    public final Function1<VideoTypeBean, Unit> getSubmit() {
        return this.submit;
    }

    public final void updateCurType(@Nullable VideoTypeBean curType) {
        this.menuAdapter.updateCur(curType);
    }
}
