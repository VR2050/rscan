package com.jbzd.media.movecartoons.p396ui.share;

import android.content.Context;
import androidx.lifecycle.LifecycleCoroutineScope;
import androidx.recyclerview.widget.RecyclerView;
import com.drake.brv.BindingAdapter;
import com.drake.brv.PageRefreshLayout;
import com.drake.brv.annotaion.DividerOrientation;
import com.gyf.immersionbar.ImmersionBar;
import com.jbzd.media.movecartoons.bean.response.ShareBean;
import com.jbzd.media.movecartoons.databinding.ActPageBinding;
import com.jbzd.media.movecartoons.p396ui.share.ShareListActivity;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.core.view.BaseBindingActivity;
import java.lang.reflect.Modifier;
import java.util.List;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Reflection;
import kotlin.jvm.internal.TypeIntrinsics;
import org.jetbrains.annotations.NotNull;
import p005b.p006a.p007a.p008a.p017r.InterfaceC0921e;
import p005b.p006a.p007a.p008a.p017r.p021n.C0944a;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p327w.p330b.p331b.p333d.C2836e;
import p379c.p380a.C3079m0;
import p379c.p380a.p381a.C2964m;
import p379c.p380a.p383b2.InterfaceC3006b;
import p403d.p404a.p405a.p407b.p408a.C4195m;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u001c\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0003\n\u0002\u0010\u000e\n\u0002\b\u0006\u0018\u0000 \u000b2\b\u0012\u0004\u0012\u00020\u00020\u0001:\u0002\u000b\fB\u0007¢\u0006\u0004\b\n\u0010\u0005J\u000f\u0010\u0004\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u0004\u0010\u0005J\u000f\u0010\u0006\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u0006\u0010\u0005J\u000f\u0010\b\u001a\u00020\u0007H\u0016¢\u0006\u0004\b\b\u0010\t¨\u0006\r"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/share/ShareListActivity;", "Lcom/qunidayede/supportlibrary/core/view/BaseBindingActivity;", "Lcom/jbzd/media/movecartoons/databinding/ActPageBinding;", "", "initView", "()V", "bindEvent", "", "getTopBarTitle", "()Ljava/lang/String;", "<init>", "Companion", "Head", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class ShareListActivity extends BaseBindingActivity<ActPageBinding> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0016\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0007\u0010\bJ\u0015\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0005\u0010\u0006¨\u0006\t"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/share/ShareListActivity$Companion;", "", "Landroid/content/Context;", "context", "", "start", "(Landroid/content/Context;)V", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final void start(@NotNull Context context) {
            C1499a.m602X(context, "context", context, ShareListActivity.class);
        }
    }

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\f\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0003\u0018\u00002\u00020\u0001B\u0007¢\u0006\u0004\b\u0002\u0010\u0003¨\u0006\u0004"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/share/ShareListActivity$Head;", "", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Head {
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    public void _$_clearFindViewByIdCache() {
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity, p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public void bindEvent() {
        ImmersionBar with = ImmersionBar.with(this);
        Intrinsics.checkExpressionValueIsNotNull(with, "this");
        with.statusBarDarkFont(true);
        with.init();
        InterfaceC3006b<List<ShareBean>> m257p = ((InterfaceC0921e) LazyKt__LazyJVMKt.lazy(C0944a.a.f472c).getValue()).m257p(1);
        Function1<List<ShareBean>, Unit> callback = new Function1<List<ShareBean>, Unit>() { // from class: com.jbzd.media.movecartoons.ui.share.ShareListActivity$bindEvent$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(List<ShareBean> list) {
                invoke2(list);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull List<ShareBean> lifecycleLoadingView) {
                ActPageBinding bodyBinding;
                Intrinsics.checkNotNullParameter(lifecycleLoadingView, "$this$lifecycleLoadingView");
                bodyBinding = ShareListActivity.this.getBodyBinding();
                PageRefreshLayout pageRefreshLayout = bodyBinding.pager;
                Intrinsics.checkNotNullExpressionValue(pageRefreshLayout, "bodyBinding.pager");
                PageRefreshLayout.m3951z(pageRefreshLayout, lifecycleLoadingView, null, null, null, 14, null);
            }
        };
        Function1<Throwable, Boolean> function1 = new Function1<Throwable, Boolean>() { // from class: com.jbzd.media.movecartoons.ui.share.ShareListActivity$bindEvent$3
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Boolean invoke(Throwable th) {
                return Boolean.valueOf(invoke2(th));
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final boolean invoke2(@NotNull Throwable it) {
                ActPageBinding bodyBinding;
                Intrinsics.checkNotNullParameter(it, "it");
                bodyBinding = ShareListActivity.this.getBodyBinding();
                PageRefreshLayout pageRefreshLayout = bodyBinding.pager;
                Intrinsics.checkNotNullExpressionValue(pageRefreshLayout, "bodyBinding.pager");
                PageRefreshLayout.m3950G(pageRefreshLayout, null, false, 3, null);
                return true;
            }
        };
        Intrinsics.checkNotNullParameter(m257p, "<this>");
        Intrinsics.checkNotNullParameter(this, "base");
        Intrinsics.checkNotNullParameter(callback, "callback");
        LifecycleCoroutineScope scope = scope();
        C3079m0 c3079m0 = C3079m0.f8432c;
        C2354n.m2435U0(scope, C2964m.f8127b, 0, new C2836e(m257p, this, false, function1, callback, null), 2, null);
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    @NotNull
    public String getTopBarTitle() {
        String string = getString(R.string.mine_share);
        Intrinsics.checkNotNullExpressionValue(string, "getString(R.string.mine_share)");
        return string;
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    public void initView() {
        bodyBinding(new Function1<ActPageBinding, Unit>() { // from class: com.jbzd.media.movecartoons.ui.share.ShareListActivity$initView$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ActPageBinding actPageBinding) {
                invoke2(actPageBinding);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull final ActPageBinding bodyBinding) {
                Intrinsics.checkNotNullParameter(bodyBinding, "$this$bodyBinding");
                RecyclerView list = bodyBinding.list;
                Intrinsics.checkNotNullExpressionValue(list, "list");
                C4195m.m4835u0(list, 0, false, false, false, 15);
                C4195m.m4784Q(list, C4195m.m4785R(12.0f), DividerOrientation.HORIZONTAL);
                C4195m.m4774J0(list, new Function2<BindingAdapter, RecyclerView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.share.ShareListActivity$initView$1.1
                    @Override // kotlin.jvm.functions.Function2
                    public /* bridge */ /* synthetic */ Unit invoke(BindingAdapter bindingAdapter, RecyclerView recyclerView) {
                        invoke2(bindingAdapter, recyclerView);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@NotNull BindingAdapter bindingAdapter, @NotNull RecyclerView recyclerView) {
                        boolean m616f0 = C1499a.m616f0(bindingAdapter, "$this$setup", recyclerView, "it", ShareListActivity.Head.class);
                        final int i2 = R.layout.item_share_head;
                        if (m616f0) {
                            bindingAdapter.f8910l.put(Reflection.typeOf(ShareListActivity.Head.class), new Function2<Object, Integer, Integer>() { // from class: com.jbzd.media.movecartoons.ui.share.ShareListActivity$initView$1$1$invoke$$inlined$addType$1
                                /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                                {
                                    super(2);
                                }

                                @NotNull
                                public final Integer invoke(@NotNull Object obj, int i3) {
                                    Intrinsics.checkNotNullParameter(obj, "$this$null");
                                    return Integer.valueOf(i2);
                                }

                                @Override // kotlin.jvm.functions.Function2
                                public /* bridge */ /* synthetic */ Integer invoke(Object obj, Integer num) {
                                    return invoke(obj, num.intValue());
                                }
                            });
                        } else {
                            bindingAdapter.f8909k.put(Reflection.typeOf(ShareListActivity.Head.class), new Function2<Object, Integer, Integer>() { // from class: com.jbzd.media.movecartoons.ui.share.ShareListActivity$initView$1$1$invoke$$inlined$addType$2
                                /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                                {
                                    super(2);
                                }

                                @NotNull
                                public final Integer invoke(@NotNull Object obj, int i3) {
                                    Intrinsics.checkNotNullParameter(obj, "$this$null");
                                    return Integer.valueOf(i2);
                                }

                                @Override // kotlin.jvm.functions.Function2
                                public /* bridge */ /* synthetic */ Integer invoke(Object obj, Integer num) {
                                    return invoke(obj, num.intValue());
                                }
                            });
                        }
                        final int i3 = R.layout.item_share;
                        if (Modifier.isInterface(ShareBean.class.getModifiers())) {
                            bindingAdapter.f8910l.put(Reflection.typeOf(ShareBean.class), new Function2<Object, Integer, Integer>() { // from class: com.jbzd.media.movecartoons.ui.share.ShareListActivity$initView$1$1$invoke$$inlined$addType$3
                                /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                                {
                                    super(2);
                                }

                                @NotNull
                                public final Integer invoke(@NotNull Object obj, int i4) {
                                    Intrinsics.checkNotNullParameter(obj, "$this$null");
                                    return Integer.valueOf(i3);
                                }

                                @Override // kotlin.jvm.functions.Function2
                                public /* bridge */ /* synthetic */ Integer invoke(Object obj, Integer num) {
                                    return invoke(obj, num.intValue());
                                }
                            });
                        } else {
                            bindingAdapter.f8909k.put(Reflection.typeOf(ShareBean.class), new Function2<Object, Integer, Integer>() { // from class: com.jbzd.media.movecartoons.ui.share.ShareListActivity$initView$1$1$invoke$$inlined$addType$4
                                /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                                {
                                    super(2);
                                }

                                @NotNull
                                public final Integer invoke(@NotNull Object obj, int i4) {
                                    Intrinsics.checkNotNullParameter(obj, "$this$null");
                                    return Integer.valueOf(i3);
                                }

                                @Override // kotlin.jvm.functions.Function2
                                public /* bridge */ /* synthetic */ Integer invoke(Object obj, Integer num) {
                                    return invoke(obj, num.intValue());
                                }
                            });
                        }
                    }
                });
                PageRefreshLayout pageRefreshLayout = bodyBinding.pager;
                final ShareListActivity shareListActivity = ShareListActivity.this;
                pageRefreshLayout.m3954D(new Function1<PageRefreshLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.share.ShareListActivity$initView$1.2
                    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                    {
                        super(1);
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@NotNull PageRefreshLayout onRefresh) {
                        Intrinsics.checkNotNullParameter(onRefresh, "$this$onRefresh");
                        InterfaceC3006b<List<ShareBean>> m257p = ((InterfaceC0921e) LazyKt__LazyJVMKt.lazy(C0944a.a.f472c).getValue()).m257p(1);
                        ShareListActivity shareListActivity2 = ShareListActivity.this;
                        PageRefreshLayout pager = bodyBinding.pager;
                        Intrinsics.checkNotNullExpressionValue(pager, "pager");
                        C2354n.m2447Y0(m257p, shareListActivity2, pager, null, 4);
                    }

                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(PageRefreshLayout pageRefreshLayout2) {
                        invoke2(pageRefreshLayout2);
                        return Unit.INSTANCE;
                    }
                });
                RecyclerView list2 = bodyBinding.list;
                Intrinsics.checkNotNullExpressionValue(list2, "list");
                BindingAdapter m4793Z = C4195m.m4793Z(list2);
                TypeIntrinsics.asMutableList(m4793Z.f8918t).add(0, new ShareListActivity.Head());
                m4793Z.notifyDataSetChanged();
            }
        });
    }
}
