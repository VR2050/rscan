package com.jbzd.media.movecartoons.p396ui.welfare;

import android.view.View;
import android.widget.TextView;
import androidx.fragment.app.FragmentActivity;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.jbzd.media.movecartoons.bean.response.WelfareBean;
import com.jbzd.media.movecartoons.core.MyThemeFragment;
import com.jbzd.media.movecartoons.p396ui.share.InviteActivity;
import com.jbzd.media.movecartoons.p396ui.welfare.WelfareTaskFragment;
import com.jbzd.media.movecartoons.view.XRefreshLayout;
import com.jbzd.media.movecartoons.view.image.CircleImageView;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.utils.GridItemDecoration;
import java.util.HashMap;
import java.util.Objects;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p009a.C0840d;
import p005b.p006a.p007a.p008a.p017r.C0917a;
import p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p340x.p354b.p355a.p356b.InterfaceC2900i;
import p005b.p340x.p354b.p355a.p360f.InterfaceC2913d;
import p379c.p380a.InterfaceC3053d1;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000b\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0010\b\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0007\u0018\u00002\n\u0012\u0006\u0012\u0004\u0018\u00010\u00020\u0001B\u0007¢\u0006\u0004\bB\u0010\u000eJ\u0017\u0010\u0006\u001a\u00020\u00052\u0006\u0010\u0004\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\u0006\u0010\u0007J\u0017\u0010\b\u001a\u00020\u00052\u0006\u0010\u0004\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\b\u0010\u0007J\u0017\u0010\t\u001a\u00020\u00052\u0006\u0010\u0004\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\t\u0010\u0007J\u0017\u0010\u000b\u001a\u00020\u00052\u0006\u0010\u0004\u001a\u00020\nH\u0002¢\u0006\u0004\b\u000b\u0010\fJ\u000f\u0010\r\u001a\u00020\u0005H\u0002¢\u0006\u0004\b\r\u0010\u000eJ\u000f\u0010\u000f\u001a\u00020\u0005H\u0016¢\u0006\u0004\b\u000f\u0010\u000eJ\u000f\u0010\u0011\u001a\u00020\u0010H\u0016¢\u0006\u0004\b\u0011\u0010\u0012J\u000f\u0010\u0013\u001a\u00020\u0005H\u0016¢\u0006\u0004\b\u0013\u0010\u000eJ\u000f\u0010\u0014\u001a\u00020\u0005H\u0016¢\u0006\u0004\b\u0014\u0010\u000eR\u001d\u0010\u001a\u001a\u00020\u00158F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0016\u0010\u0017\u001a\u0004\b\u0018\u0010\u0019R\u001d\u0010\u001f\u001a\u00020\u001b8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u001c\u0010\u0017\u001a\u0004\b\u001d\u0010\u001eR\u001d\u0010\"\u001a\u00020\u00158F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b \u0010\u0017\u001a\u0004\b!\u0010\u0019R\u0018\u0010$\u001a\u0004\u0018\u00010#8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b$\u0010%R\u001d\u0010*\u001a\u00020&8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b'\u0010\u0017\u001a\u0004\b(\u0010)R\u001d\u0010-\u001a\u00020\u00158F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b+\u0010\u0017\u001a\u0004\b,\u0010\u0019R\u0016\u0010/\u001a\u00020.8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b/\u00100R\u001d\u00103\u001a\u00020\u001b8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b1\u0010\u0017\u001a\u0004\b2\u0010\u001eR\u001d\u00106\u001a\u00020\u00158F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b4\u0010\u0017\u001a\u0004\b5\u0010\u0019R\u001d\u0010;\u001a\u0002078F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b8\u0010\u0017\u001a\u0004\b9\u0010:R\u0016\u0010=\u001a\u00020<8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b=\u0010>R\u001d\u0010A\u001a\u00020\u00158F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b?\u0010\u0017\u001a\u0004\b@\u0010\u0019¨\u0006C"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/welfare/WelfareTaskFragment;", "Lcom/jbzd/media/movecartoons/core/MyThemeFragment;", "", "Lcom/jbzd/media/movecartoons/bean/response/WelfareBean$TaskItem;", "item", "", "doAction", "(Lcom/jbzd/media/movecartoons/bean/response/WelfareBean$TaskItem;)V", "doRecept", "doDownload", "Lcom/jbzd/media/movecartoons/bean/response/WelfareBean$SignItem;", "userDoDaySign", "(Lcom/jbzd/media/movecartoons/bean/response/WelfareBean$SignItem;)V", "getInfo", "()V", "onDestroy", "", "getLayout", "()I", "initViews", "onResume", "Landroid/widget/TextView;", "tv_signed_day$delegate", "Lkotlin/Lazy;", "getTv_signed_day", "()Landroid/widget/TextView;", "tv_signed_day", "Landroidx/recyclerview/widget/RecyclerView;", "rv_signed$delegate", "getRv_signed", "()Landroidx/recyclerview/widget/RecyclerView;", "rv_signed", "tv_sign_now$delegate", "getTv_sign_now", "tv_sign_now", "Lc/a/d1;", "job", "Lc/a/d1;", "Lcom/jbzd/media/movecartoons/view/XRefreshLayout;", "refresh_layout_fltask$delegate", "getRefresh_layout_fltask", "()Lcom/jbzd/media/movecartoons/view/XRefreshLayout;", "refresh_layout_fltask", "tv_role$delegate", "getTv_role", "tv_role", "Lcom/jbzd/media/movecartoons/ui/welfare/WelfareTaskSignAdapter;", "mWelfareTaskSignAdapter", "Lcom/jbzd/media/movecartoons/ui/welfare/WelfareTaskSignAdapter;", "rv_task$delegate", "getRv_task", "rv_task", "tv_score_user_current$delegate", "getTv_score_user_current", "tv_score_user_current", "Lcom/jbzd/media/movecartoons/view/image/CircleImageView;", "iv_user_avatar$delegate", "getIv_user_avatar", "()Lcom/jbzd/media/movecartoons/view/image/CircleImageView;", "iv_user_avatar", "Lcom/jbzd/media/movecartoons/ui/welfare/WelfareTaskAdapter;", "mTaskAdapter", "Lcom/jbzd/media/movecartoons/ui/welfare/WelfareTaskAdapter;", "tv_tip_text$delegate", "getTv_tip_text", "tv_tip_text", "<init>", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class WelfareTaskFragment extends MyThemeFragment<Object> {

    /* renamed from: iv_user_avatar$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy iv_user_avatar;

    @Nullable
    private InterfaceC3053d1 job;

    @NotNull
    private WelfareTaskAdapter mTaskAdapter;

    @NotNull
    private WelfareTaskSignAdapter mWelfareTaskSignAdapter;

    /* renamed from: refresh_layout_fltask$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy refresh_layout_fltask;

    /* renamed from: rv_signed$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rv_signed;

    /* renamed from: rv_task$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rv_task;

    /* renamed from: tv_role$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_role;

    /* renamed from: tv_score_user_current$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_score_user_current;

    /* renamed from: tv_sign_now$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_sign_now;

    /* renamed from: tv_signed_day$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_signed_day;

    /* renamed from: tv_tip_text$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_tip_text;

    public WelfareTaskFragment() {
        WelfareTaskAdapter welfareTaskAdapter = new WelfareTaskAdapter();
        welfareTaskAdapter.setOnItemClickListener(new InterfaceC1304d() { // from class: b.a.a.a.t.t.e
            @Override // p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d
            public final void onItemClick(BaseQuickAdapter baseQuickAdapter, View view, int i2) {
                WelfareTaskFragment.m6026mTaskAdapter$lambda1$lambda0(WelfareTaskFragment.this, baseQuickAdapter, view, i2);
            }
        });
        Unit unit = Unit.INSTANCE;
        this.mTaskAdapter = welfareTaskAdapter;
        WelfareTaskSignAdapter welfareTaskSignAdapter = new WelfareTaskSignAdapter();
        welfareTaskSignAdapter.setOnItemClickListener(new InterfaceC1304d() { // from class: b.a.a.a.t.t.c
            @Override // p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d
            public final void onItemClick(BaseQuickAdapter baseQuickAdapter, View view, int i2) {
                WelfareTaskFragment.m6027mWelfareTaskSignAdapter$lambda3$lambda2(baseQuickAdapter, view, i2);
            }
        });
        this.mWelfareTaskSignAdapter = welfareTaskSignAdapter;
        this.refresh_layout_fltask = LazyKt__LazyJVMKt.lazy(new Function0<XRefreshLayout>() { // from class: com.jbzd.media.movecartoons.ui.welfare.WelfareTaskFragment$refresh_layout_fltask$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final XRefreshLayout invoke() {
                View view = WelfareTaskFragment.this.getView();
                XRefreshLayout xRefreshLayout = view == null ? null : (XRefreshLayout) view.findViewById(R.id.refresh_layout_fltask);
                Intrinsics.checkNotNull(xRefreshLayout);
                return xRefreshLayout;
            }
        });
        this.tv_sign_now = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.welfare.WelfareTaskFragment$tv_sign_now$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final TextView invoke() {
                View view = WelfareTaskFragment.this.getView();
                TextView textView = view == null ? null : (TextView) view.findViewById(R.id.tv_sign_now);
                Intrinsics.checkNotNull(textView);
                return textView;
            }
        });
        this.tv_tip_text = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.welfare.WelfareTaskFragment$tv_tip_text$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final TextView invoke() {
                View view = WelfareTaskFragment.this.getView();
                TextView textView = view == null ? null : (TextView) view.findViewById(R.id.tv_tip_text);
                Intrinsics.checkNotNull(textView);
                return textView;
            }
        });
        this.tv_role = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.welfare.WelfareTaskFragment$tv_role$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final TextView invoke() {
                View view = WelfareTaskFragment.this.getView();
                TextView textView = view == null ? null : (TextView) view.findViewById(R.id.tv_role);
                Intrinsics.checkNotNull(textView);
                return textView;
            }
        });
        this.tv_score_user_current = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.welfare.WelfareTaskFragment$tv_score_user_current$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final TextView invoke() {
                View view = WelfareTaskFragment.this.getView();
                TextView textView = view == null ? null : (TextView) view.findViewById(R.id.tv_score_user_current);
                Intrinsics.checkNotNull(textView);
                return textView;
            }
        });
        this.tv_signed_day = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.welfare.WelfareTaskFragment$tv_signed_day$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final TextView invoke() {
                View view = WelfareTaskFragment.this.getView();
                TextView textView = view == null ? null : (TextView) view.findViewById(R.id.tv_signed_day);
                Intrinsics.checkNotNull(textView);
                return textView;
            }
        });
        this.rv_signed = LazyKt__LazyJVMKt.lazy(new Function0<RecyclerView>() { // from class: com.jbzd.media.movecartoons.ui.welfare.WelfareTaskFragment$rv_signed$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final RecyclerView invoke() {
                View view = WelfareTaskFragment.this.getView();
                RecyclerView recyclerView = view == null ? null : (RecyclerView) view.findViewById(R.id.rv_signed);
                Intrinsics.checkNotNull(recyclerView);
                return recyclerView;
            }
        });
        this.rv_task = LazyKt__LazyJVMKt.lazy(new Function0<RecyclerView>() { // from class: com.jbzd.media.movecartoons.ui.welfare.WelfareTaskFragment$rv_task$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final RecyclerView invoke() {
                View view = WelfareTaskFragment.this.getView();
                RecyclerView recyclerView = view == null ? null : (RecyclerView) view.findViewById(R.id.rv_task);
                Intrinsics.checkNotNull(recyclerView);
                return recyclerView;
            }
        });
        this.iv_user_avatar = LazyKt__LazyJVMKt.lazy(new Function0<CircleImageView>() { // from class: com.jbzd.media.movecartoons.ui.welfare.WelfareTaskFragment$iv_user_avatar$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final CircleImageView invoke() {
                View view = WelfareTaskFragment.this.getView();
                CircleImageView circleImageView = view == null ? null : (CircleImageView) view.findViewById(R.id.iv_user_avatar);
                Intrinsics.checkNotNull(circleImageView);
                return circleImageView;
            }
        });
    }

    private final void doAction(WelfareBean.TaskItem item) {
        if (Intrinsics.areEqual(item.status, "0")) {
            doDownload(item);
        } else if (Intrinsics.areEqual(item.status, "1")) {
            doRecept(item);
        }
    }

    private final void doDownload(final WelfareBean.TaskItem item) {
        C0917a c0917a = C0917a.f372a;
        HashMap hashMap = new HashMap();
        hashMap.put("id", item.f10003id);
        Unit unit = Unit.INSTANCE;
        this.job = C0917a.m221e(c0917a, "user/doTaskLog", String.class, hashMap, new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.welfare.WelfareTaskFragment$doDownload$2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(String str) {
                invoke2(str);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable String str) {
                C0840d.a aVar = C0840d.f235a;
                FragmentActivity requireActivity = WelfareTaskFragment.this.requireActivity();
                Intrinsics.checkNotNullExpressionValue(requireActivity, "requireActivity()");
                C0840d.a.m174d(aVar, requireActivity, item.link, null, null, 12);
            }
        }, null, false, false, null, false, 496);
    }

    private final void doRecept(WelfareBean.TaskItem item) {
        C0917a c0917a = C0917a.f372a;
        HashMap hashMap = new HashMap();
        hashMap.put("id", item.f10003id);
        Unit unit = Unit.INSTANCE;
        this.job = C0917a.m221e(c0917a, "user/doTask", String.class, hashMap, new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.welfare.WelfareTaskFragment$doRecept$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(String str) {
                invoke2(str);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable String str) {
                WelfareTaskFragment.this.getInfo();
            }
        }, null, false, false, null, false, 496);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void getInfo() {
        this.job = C0917a.m221e(C0917a.f372a, "user/task", WelfareBean.class, new HashMap(), new Function1<WelfareBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.welfare.WelfareTaskFragment$getInfo$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(WelfareBean welfareBean) {
                invoke2(welfareBean);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable WelfareBean welfareBean) {
                WelfareTaskSignAdapter welfareTaskSignAdapter;
                WelfareTaskSignAdapter welfareTaskSignAdapter2;
                WelfareTaskAdapter welfareTaskAdapter;
                WelfareTaskAdapter welfareTaskAdapter2;
                if (welfareBean == null) {
                    return;
                }
                WelfareTaskFragment welfareTaskFragment = WelfareTaskFragment.this;
                welfareTaskFragment.getRefresh_layout_fltask().finishRefresh();
                welfareTaskFragment.getTv_tip_text().setText(welfareBean.task_tips);
                welfareTaskFragment.getTv_role().setText(welfareBean.user.nickname);
                welfareTaskFragment.getTv_score_user_current().setText(Intrinsics.stringPlus("累计积分：", welfareBean.user.integral));
                welfareTaskFragment.getTv_signed_day().setText(welfareBean.sign.info);
                if (welfareBean.sign.has_done.equals("y")) {
                    welfareTaskFragment.getTv_sign_now().setText("今日已签到");
                    welfareTaskFragment.getTv_sign_now().setBackground(welfareTaskFragment.getResources().getDrawable(R.drawable.btn_orange_style));
                }
                RecyclerView rv_signed = welfareTaskFragment.getRv_signed();
                welfareTaskSignAdapter = welfareTaskFragment.mWelfareTaskSignAdapter;
                welfareTaskSignAdapter.setNewData(welfareBean.sign.items);
                welfareTaskSignAdapter2 = welfareTaskFragment.mWelfareTaskSignAdapter;
                rv_signed.setAdapter(welfareTaskSignAdapter2);
                rv_signed.setLayoutManager(new GridLayoutManager(welfareTaskFragment.requireContext(), 4));
                if (rv_signed.getItemDecorationCount() == 0) {
                    GridItemDecoration.C4053a c4053a = new GridItemDecoration.C4053a(rv_signed.getContext());
                    c4053a.f10336d = C1499a.m638x(c4053a, R.color.transparent, rv_signed, 8.0d);
                    c4053a.f10337e = C2354n.m2437V(rv_signed.getContext(), 8.0d);
                    c4053a.f10339g = false;
                    c4053a.f10340h = false;
                    c4053a.f10338f = false;
                    C1499a.m604Z(c4053a, rv_signed);
                }
                welfareTaskAdapter = welfareTaskFragment.mTaskAdapter;
                welfareTaskAdapter.setNewData(welfareBean.task_items);
                RecyclerView rv_task = welfareTaskFragment.getRv_task();
                welfareTaskAdapter2 = welfareTaskFragment.mTaskAdapter;
                rv_task.setAdapter(welfareTaskAdapter2);
                C2354n.m2467d2(welfareTaskFragment.requireActivity()).m3298p(welfareBean.user.img).m3288b0().m757R(welfareTaskFragment.getIv_user_avatar());
            }
        }, null, false, false, null, false, 496);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initViews$lambda-6, reason: not valid java name */
    public static final void m6025initViews$lambda6(WelfareTaskFragment this$0, InterfaceC2900i it) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(it, "it");
        this$0.getInfo();
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: mTaskAdapter$lambda-1$lambda-0, reason: not valid java name */
    public static final void m6026mTaskAdapter$lambda1$lambda0(WelfareTaskFragment this$0, BaseQuickAdapter adapter, View view, int i2) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
        Object obj = adapter.getData().get(i2);
        Objects.requireNonNull(obj, "null cannot be cast to non-null type com.jbzd.media.movecartoons.bean.response.WelfareBean.TaskItem");
        WelfareBean.TaskItem taskItem = (WelfareBean.TaskItem) obj;
        String str = taskItem.type;
        if (str != null) {
            int hashCode = str.hashCode();
            if (hashCode == 103149417) {
                if (str.equals("login")) {
                    this$0.doRecept(taskItem);
                }
            } else {
                if (hashCode != 109400031) {
                    if (hashCode == 1427818632 && str.equals("download")) {
                        this$0.doAction(taskItem);
                        return;
                    }
                    return;
                }
                if (str.equals("share")) {
                    InviteActivity.Companion companion = InviteActivity.INSTANCE;
                    FragmentActivity requireActivity = this$0.requireActivity();
                    Intrinsics.checkNotNullExpressionValue(requireActivity, "requireActivity()");
                    companion.start(requireActivity);
                }
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: mWelfareTaskSignAdapter$lambda-3$lambda-2, reason: not valid java name */
    public static final void m6027mWelfareTaskSignAdapter$lambda3$lambda2(BaseQuickAdapter adapter, View view, int i2) {
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void userDoDaySign(WelfareBean.SignItem item) {
        C0917a c0917a = C0917a.f372a;
        HashMap hashMap = new HashMap();
        hashMap.put("num", item.num);
        Unit unit = Unit.INSTANCE;
        this.job = C0917a.m221e(c0917a, "user/doDaySign", String.class, hashMap, new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.welfare.WelfareTaskFragment$userDoDaySign$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(String str) {
                invoke2(str);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable String str) {
                WelfareTaskFragment.this.getInfo();
            }
        }, null, false, false, null, false, 496);
    }

    @Override // com.jbzd.media.movecartoons.core.MyThemeFragment, com.qunidayede.supportlibrary.core.view.BaseThemeFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    @NotNull
    public final CircleImageView getIv_user_avatar() {
        return (CircleImageView) this.iv_user_avatar.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public int getLayout() {
        return R.layout.fragment_exchange;
    }

    @NotNull
    public final XRefreshLayout getRefresh_layout_fltask() {
        return (XRefreshLayout) this.refresh_layout_fltask.getValue();
    }

    @NotNull
    public final RecyclerView getRv_signed() {
        return (RecyclerView) this.rv_signed.getValue();
    }

    @NotNull
    public final RecyclerView getRv_task() {
        return (RecyclerView) this.rv_task.getValue();
    }

    @NotNull
    public final TextView getTv_role() {
        return (TextView) this.tv_role.getValue();
    }

    @NotNull
    public final TextView getTv_score_user_current() {
        return (TextView) this.tv_score_user_current.getValue();
    }

    @NotNull
    public final TextView getTv_sign_now() {
        return (TextView) this.tv_sign_now.getValue();
    }

    @NotNull
    public final TextView getTv_signed_day() {
        return (TextView) this.tv_signed_day.getValue();
    }

    @NotNull
    public final TextView getTv_tip_text() {
        return (TextView) this.tv_tip_text.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public void initViews() {
        super.initViews();
        getRefresh_layout_fltask().setOnRefreshListener(new InterfaceC2913d() { // from class: b.a.a.a.t.t.d
            @Override // p005b.p340x.p354b.p355a.p360f.InterfaceC2913d
            /* renamed from: b */
            public final void mo302b(InterfaceC2900i interfaceC2900i) {
                WelfareTaskFragment.m6025initViews$lambda6(WelfareTaskFragment.this, interfaceC2900i);
            }
        });
        C2354n.m2374A(getTv_sign_now(), 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.welfare.WelfareTaskFragment$initViews$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(TextView textView) {
                invoke2(textView);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull TextView it) {
                WelfareTaskSignAdapter welfareTaskSignAdapter;
                Intrinsics.checkNotNullParameter(it, "it");
                WelfareTaskFragment welfareTaskFragment = WelfareTaskFragment.this;
                welfareTaskSignAdapter = welfareTaskFragment.mWelfareTaskSignAdapter;
                welfareTaskFragment.userDoDaySign(welfareTaskSignAdapter.getItem(0));
            }
        }, 1);
    }

    @Override // androidx.fragment.app.Fragment
    public void onDestroy() {
        super.onDestroy();
        cancelJob(this.job);
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment, androidx.fragment.app.Fragment
    public void onResume() {
        super.onResume();
        getInfo();
    }
}
