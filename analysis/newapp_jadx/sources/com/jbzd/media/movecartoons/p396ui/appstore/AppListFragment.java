package com.jbzd.media.movecartoons.p396ui.appstore;

import android.annotation.SuppressLint;
import android.content.Context;
import android.view.View;
import android.widget.ImageView;
import androidx.core.app.NotificationCompat;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.jbzd.media.movecartoons.bean.response.AppBean;
import com.jbzd.media.movecartoons.bean.response.AppItemNew;
import com.jbzd.media.movecartoons.bean.response.home.AdBean;
import com.jbzd.media.movecartoons.core.BaseListFragment;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.core.view.BaseFragment;
import java.util.HashMap;
import java.util.List;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.CollectionsKt___CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt__StringsKt;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p009a.C0840d;
import p005b.p006a.p007a.p008a.p009a.C0843e0;
import p005b.p006a.p007a.p008a.p009a.C0844f;
import p005b.p006a.p007a.p008a.p009a.C0859m0;
import p005b.p006a.p007a.p008a.p009a.C0869q;
import p005b.p006a.p007a.p008a.p017r.C0917a;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p293n.p294a.C2657k0;
import p005b.p293n.p294a.InterfaceC2652i;
import p379c.p380a.C3079m0;
import p379c.p380a.C3109w0;
import p379c.p380a.InterfaceC3053d1;
import p426f.p427a.p428a.C4325a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000Z\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u000b\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\b\u0018\u0000 *2\b\u0012\u0004\u0012\u00020\u00020\u0001:\u0001*B\u0007¢\u0006\u0004\b)\u0010\u0018J2\u0010\n\u001a\u00020\b2!\u0010\t\u001a\u001d\u0012\u0013\u0012\u00110\u0004¢\u0006\f\b\u0005\u0012\b\b\u0006\u0012\u0004\b\b(\u0007\u0012\u0004\u0012\u00020\b0\u0003H\u0003¢\u0006\u0004\b\n\u0010\u000bJ\u000f\u0010\r\u001a\u00020\fH\u0016¢\u0006\u0004\b\r\u0010\u000eJ\u000f\u0010\u0010\u001a\u00020\u000fH\u0016¢\u0006\u0004\b\u0010\u0010\u0011J\u001f\u0010\u0015\u001a\u00020\b2\u0006\u0010\u0013\u001a\u00020\u00122\u0006\u0010\u0014\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0015\u0010\u0016J\u000f\u0010\u0017\u001a\u00020\bH\u0016¢\u0006\u0004\b\u0017\u0010\u0018J\u000f\u0010\u001a\u001a\u00020\u0019H\u0016¢\u0006\u0004\b\u001a\u0010\u001bJ3\u0010!\u001a\u00020\b2\u0012\u0010\u001d\u001a\u000e\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u00120\u001c2\u0006\u0010\u001f\u001a\u00020\u001e2\u0006\u0010 \u001a\u00020\u000fH\u0016¢\u0006\u0004\b!\u0010\"R\u001d\u0010(\u001a\u00020#8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b$\u0010%\u001a\u0004\b&\u0010'¨\u0006+"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/appstore/AppListFragment;", "Lcom/jbzd/media/movecartoons/core/BaseListFragment;", "Lcom/jbzd/media/movecartoons/bean/response/AppItemNew;", "Lkotlin/Function1;", "", "Lkotlin/ParameterName;", "name", "pass", "", "resultBlock", "permissionCheck", "(Lkotlin/jvm/functions/Function1;)V", "Landroidx/recyclerview/widget/RecyclerView$LayoutManager;", "getLayoutManager", "()Landroidx/recyclerview/widget/RecyclerView$LayoutManager;", "", "getItemLayoutId", "()I", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "helper", "item", "bindItem", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lcom/jbzd/media/movecartoons/bean/response/AppItemNew;)V", "registerItemChildEvent", "()V", "Lc/a/d1;", "request", "()Lc/a/d1;", "Lcom/chad/library/adapter/base/BaseQuickAdapter;", "adapter", "Landroid/view/View;", "view", "position", "onItemChildClick", "(Lcom/chad/library/adapter/base/BaseQuickAdapter;Landroid/view/View;I)V", "Lb/a/a/a/a/q;", "downloadUtils$delegate", "Lkotlin/Lazy;", "getDownloadUtils", "()Lb/a/a/a/a/q;", "downloadUtils", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class AppListFragment extends BaseListFragment<AppItemNew> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);
    public static Function1<? super List<? extends AdBean>, Unit> callBack;

    /* renamed from: downloadUtils$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy downloadUtils = LazyKt__LazyJVMKt.lazy(new Function0<C0869q>() { // from class: com.jbzd.media.movecartoons.ui.appstore.AppListFragment$downloadUtils$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final C0869q invoke() {
            Context requireContext = AppListFragment.this.requireContext();
            Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
            return new C0869q(requireContext);
        }
    });

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000*\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u000b\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0013\u0010\u0014J6\u0010\u000b\u001a\u00020\n2'\u0010\t\u001a#\u0012\u0019\u0012\u0017\u0012\u0004\u0012\u00020\u00040\u0003¢\u0006\f\b\u0005\u0012\b\b\u0006\u0012\u0004\b\b(\u0007\u0012\u0004\u0012\u00020\b0\u0002¢\u0006\u0004\b\u000b\u0010\fRC\u0010\r\u001a#\u0012\u0019\u0012\u0017\u0012\u0004\u0012\u00020\u00040\u0003¢\u0006\f\b\u0005\u0012\b\b\u0006\u0012\u0004\b\b(\u0007\u0012\u0004\u0012\u00020\b0\u00028\u0006@\u0006X\u0086.¢\u0006\u0012\n\u0004\b\r\u0010\u000e\u001a\u0004\b\u000f\u0010\u0010\"\u0004\b\u0011\u0010\u0012¨\u0006\u0015"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/appstore/AppListFragment$Companion;", "", "Lkotlin/Function1;", "", "Lcom/jbzd/media/movecartoons/bean/response/home/AdBean;", "Lkotlin/ParameterName;", "name", "banner", "", NotificationCompat.CATEGORY_CALL, "Lcom/jbzd/media/movecartoons/ui/appstore/AppListFragment;", "newInstance", "(Lkotlin/jvm/functions/Function1;)Lcom/jbzd/media/movecartoons/ui/appstore/AppListFragment;", "callBack", "Lkotlin/jvm/functions/Function1;", "getCallBack", "()Lkotlin/jvm/functions/Function1;", "setCallBack", "(Lkotlin/jvm/functions/Function1;)V", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final Function1<List<? extends AdBean>, Unit> getCallBack() {
            Function1 function1 = AppListFragment.callBack;
            if (function1 != null) {
                return function1;
            }
            Intrinsics.throwUninitializedPropertyAccessException("callBack");
            throw null;
        }

        @NotNull
        public final AppListFragment newInstance(@NotNull Function1<? super List<? extends AdBean>, Unit> call) {
            Intrinsics.checkNotNullParameter(call, "call");
            AppListFragment appListFragment = new AppListFragment();
            AppListFragment.INSTANCE.setCallBack(call);
            return appListFragment;
        }

        public final void setCallBack(@NotNull Function1<? super List<? extends AdBean>, Unit> function1) {
            Intrinsics.checkNotNullParameter(function1, "<set-?>");
            AppListFragment.callBack = function1;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final C0869q getDownloadUtils() {
        return (C0869q) this.downloadUtils.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    @SuppressLint({"CheckResult"})
    public final void permissionCheck(final Function1<? super Boolean, Unit> resultBlock) {
        C2657k0 c2657k0 = new C2657k0(getActivity());
        c2657k0.m3155a("android.permission.READ_EXTERNAL_STORAGE");
        c2657k0.m3155a("android.permission.WRITE_EXTERNAL_STORAGE");
        c2657k0.m3156b(new InterfaceC2652i() { // from class: com.jbzd.media.movecartoons.ui.appstore.AppListFragment$permissionCheck$1
            @Override // p005b.p293n.p294a.InterfaceC2652i
            public void onDenied(@NotNull List<String> permissions, boolean doNotAskAgain) {
                Intrinsics.checkNotNullParameter(permissions, "permissions");
                if (!doNotAskAgain) {
                    C4325a.m4899b(AppListFragment.this.requireContext(), "没有权限").show();
                } else {
                    C4325a.m4899b(AppListFragment.this.requireContext(), "被永久拒绝授权").show();
                    C2657k0.m3154c(AppListFragment.this, permissions);
                }
            }

            @Override // p005b.p293n.p294a.InterfaceC2652i
            public void onGranted(@NotNull List<String> permissions, boolean allGranted) {
                Intrinsics.checkNotNullParameter(permissions, "permissions");
                if (allGranted) {
                    resultBlock.invoke(Boolean.TRUE);
                } else {
                    C4325a.m4899b(AppListFragment.this.requireContext(), "获取部分权限成功，但部分权限未正常授予").show();
                }
            }
        });
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment, com.jbzd.media.movecartoons.core.MyThemeFragment, com.qunidayede.supportlibrary.core.view.BaseThemeFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public int getItemLayoutId() {
        return R.layout.item_appstore;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    @NotNull
    public RecyclerView.LayoutManager getLayoutManager() {
        return new GridLayoutManager(requireContext(), 1);
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public void onItemChildClick(@NotNull BaseQuickAdapter<AppItemNew, BaseViewHolder> adapter, @NotNull View view, int position) {
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
        super.onItemChildClick(adapter, view, position);
        AppItemNew bean = adapter.getItem(position);
        String str = bean.android_url;
        if (str != null) {
            Intrinsics.checkNotNullExpressionValue(str, "item.android_url");
            if (Intrinsics.areEqual(CollectionsKt___CollectionsKt.last(StringsKt__StringsKt.split$default((CharSequence) str, new String[]{"."}, false, 0, 6, (Object) null)), "apk")) {
                BaseFragment.showLoadingDialog$default(this, null, true, 1, null);
                C3109w0 c3109w0 = C3109w0.f8471c;
                C3079m0 c3079m0 = C3079m0.f8432c;
                C2354n.m2435U0(c3109w0, C3079m0.f8431b, 0, new AppListFragment$onItemChildClick$1(this, bean, adapter, position, null), 2, null);
                return;
            }
            C0840d.a aVar = C0840d.f235a;
            Context context = requireContext();
            Intrinsics.checkNotNullExpressionValue(context, "requireContext()");
            Intrinsics.checkNotNullParameter(context, "context");
            Intrinsics.checkNotNullParameter(bean, "bean");
            String id = bean.f9930id;
            Intrinsics.checkNotNullExpressionValue(id, "bean.id");
            String name = bean.name;
            Intrinsics.checkNotNullExpressionValue(name, "bean.name");
            Intrinsics.checkNotNullParameter("app", "type");
            Intrinsics.checkNotNullParameter(id, "id");
            Intrinsics.checkNotNullParameter(name, "name");
            C0917a c0917a = C0917a.f372a;
            HashMap m596R = C1499a.m596R("object_type", "app", "object_id", id);
            m596R.put("object_name", name);
            Unit unit = Unit.INSTANCE;
            C0917a.m221e(c0917a, "system/track", Object.class, m596R, C0844f.f245c, null, false, false, null, false, 432);
            C0840d.a.m174d(aVar, context, bean.android_url, null, null, 12);
        }
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public void registerItemChildEvent() {
        registerItemChildClick(R.id.btnDownload);
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    @NotNull
    public InterfaceC3053d1 request() {
        C0917a c0917a = C0917a.f372a;
        HashMap hashMap = new HashMap();
        hashMap.put("page", String.valueOf(getCurrentPage()));
        Unit unit = Unit.INSTANCE;
        return C0917a.m221e(c0917a, "system/appStore", AppBean.class, hashMap, new Function1<AppBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.appstore.AppListFragment$request$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(AppBean appBean) {
                invoke2(appBean);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable AppBean appBean) {
                if (appBean != null) {
                    AppListFragment.this.didRequestComplete(appBean.items);
                }
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.appstore.AppListFragment$request$3
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                invoke2(exc);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull Exception it) {
                Intrinsics.checkNotNullParameter(it, "it");
                AppListFragment.this.didRequestError();
            }
        }, false, false, null, false, 480);
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public void bindItem(@NotNull BaseViewHolder helper, @NotNull AppItemNew item) {
        Intrinsics.checkNotNullParameter(helper, "helper");
        Intrinsics.checkNotNullParameter(item, "item");
        String str = item.name;
        if (str == null) {
            str = "";
        }
        helper.m3919i(R.id.tv_appstore_appname, str);
        helper.m3919i(R.id.tv_click_num, Intrinsics.stringPlus(C0843e0.m182a(item.download), "次下载"));
        String str2 = item.description;
        helper.m3919i(R.id.tv_appstore_des, str2 != null ? str2 : "");
        C2354n.m2455a2(requireContext()).m3298p(item.image).m757R((ImageView) helper.m3912b(R.id.iv_cover_appitem));
        View view = helper.m3912b(R.id.iv_cover_appitem);
        Intrinsics.checkNotNullParameter(view, "view");
        view.setOutlineProvider(new C0859m0(10.0d));
        view.setClipToOutline(true);
    }
}
