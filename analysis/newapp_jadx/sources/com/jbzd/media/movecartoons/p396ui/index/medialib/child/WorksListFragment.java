package com.jbzd.media.movecartoons.p396ui.index.medialib.child;

import android.view.View;
import android.widget.ImageView;
import androidx.core.app.NotificationCompat;
import androidx.recyclerview.widget.RecyclerView;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.jbzd.media.movecartoons.bean.response.WorksBean;
import com.jbzd.media.movecartoons.core.BaseListFragment;
import com.jbzd.media.movecartoons.p396ui.dialog.HistoryBottomDialog;
import com.jbzd.media.movecartoons.p396ui.movie.fragment.RecommendFragment;
import com.jbzd.media.movecartoons.view.decoration.ItemDecorationV;
import com.qnmd.adnnm.da0yzo.R;
import java.util.HashMap;
import java.util.List;
import kotlin.Deprecated;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p009a.C0859m0;
import p005b.p006a.p007a.p008a.p017r.C0917a;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p143g.p144a.C1558h;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p327w.p330b.p336c.C2851b;
import p005b.p327w.p330b.p336c.C2852c;
import p379c.p380a.InterfaceC3053d1;

@Deprecated(message = "has no this page!!")
@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000^\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0010\u000e\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\n\b\u0007\u0018\u0000 02\b\u0012\u0004\u0012\u00020\u00020\u0001:\u00010B\u0007¢\u0006\u0004\b/\u0010\u0011J!\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0003\u001a\u00020\u00022\b\b\u0002\u0010\u0005\u001a\u00020\u0004H\u0002¢\u0006\u0004\b\u0007\u0010\bJ\u000f\u0010\n\u001a\u00020\tH\u0016¢\u0006\u0004\b\n\u0010\u000bJ\u001f\u0010\u000e\u001a\u00020\u00062\u0006\u0010\r\u001a\u00020\f2\u0006\u0010\u0003\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u000e\u0010\u000fJ\u000f\u0010\u0010\u001a\u00020\u0006H\u0016¢\u0006\u0004\b\u0010\u0010\u0011J3\u0010\u0017\u001a\u00020\u00062\u0012\u0010\u0013\u001a\u000e\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\f0\u00122\u0006\u0010\u0015\u001a\u00020\u00142\u0006\u0010\u0016\u001a\u00020\tH\u0016¢\u0006\u0004\b\u0017\u0010\u0018J\u000f\u0010\u0019\u001a\u00020\u0006H\u0016¢\u0006\u0004\b\u0019\u0010\u0011J\u0017\u0010\u001c\u001a\u00020\u00062\b\u0010\u001b\u001a\u0004\u0018\u00010\u001a¢\u0006\u0004\b\u001c\u0010\u001dJ\u0017\u0010\u001f\u001a\u00020\u00062\b\u0010\u001e\u001a\u0004\u0018\u00010\u001a¢\u0006\u0004\b\u001f\u0010\u001dJ\u0011\u0010!\u001a\u0004\u0018\u00010 H\u0016¢\u0006\u0004\b!\u0010\"J\u0011\u0010$\u001a\u0004\u0018\u00010#H\u0016¢\u0006\u0004\b$\u0010%R9\u0010,\u001a\u001e\u0012\u0004\u0012\u00020\u001a\u0012\u0004\u0012\u00020\u001a0&j\u000e\u0012\u0004\u0012\u00020\u001a\u0012\u0004\u0012\u00020\u001a`'8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b(\u0010)\u001a\u0004\b*\u0010+R\u0018\u0010-\u001a\u0004\u0018\u00010 8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b-\u0010.¨\u00061"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/medialib/child/WorksListFragment;", "Lcom/jbzd/media/movecartoons/core/BaseListFragment;", "Lcom/jbzd/media/movecartoons/bean/response/WorksBean;", "item", "", "hasLoading", "", "delWorks", "(Lcom/jbzd/media/movecartoons/bean/response/WorksBean;Z)V", "", "getItemLayoutId", "()I", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "helper", "bindItem", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lcom/jbzd/media/movecartoons/bean/response/WorksBean;)V", "registerItemChildEvent", "()V", "Lcom/chad/library/adapter/base/BaseQuickAdapter;", "adapter", "Landroid/view/View;", "view", "position", "onItemChildClick", "(Lcom/chad/library/adapter/base/BaseQuickAdapter;Landroid/view/View;I)V", "onDestroyView", "", NotificationCompat.CATEGORY_STATUS, "updateStatus", "(Ljava/lang/String;)V", "canvas", "updateCanvas", "Lc/a/d1;", "request", "()Lc/a/d1;", "Landroidx/recyclerview/widget/RecyclerView$ItemDecoration;", "getItemDecoration", "()Landroidx/recyclerview/widget/RecyclerView$ItemDecoration;", "Ljava/util/HashMap;", "Lkotlin/collections/HashMap;", "body$delegate", "Lkotlin/Lazy;", "getBody", "()Ljava/util/HashMap;", "body", "delJob", "Lc/a/d1;", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class WorksListFragment extends BaseListFragment<WorksBean> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    /* renamed from: body$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy body = LazyKt__LazyJVMKt.lazy(new Function0<HashMap<String, String>>() { // from class: com.jbzd.media.movecartoons.ui.index.medialib.child.WorksListFragment$body$2
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final HashMap<String, String> invoke() {
            return C1499a.m596R(NotificationCompat.CATEGORY_STATUS, "", "canvas", "");
        }
    });

    @Nullable
    private InterfaceC3053d1 delJob;

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0010\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0005\u0010\u0006J\r\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0003\u0010\u0004¨\u0006\u0007"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/medialib/child/WorksListFragment$Companion;", "", "Lcom/jbzd/media/movecartoons/ui/index/medialib/child/WorksListFragment;", "newInstance", "()Lcom/jbzd/media/movecartoons/ui/index/medialib/child/WorksListFragment;", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final WorksListFragment newInstance() {
            return new WorksListFragment();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void delWorks(final WorksBean item, boolean hasLoading) {
        if (hasLoading) {
            showLoadingDialog("", true);
        }
        HashMap hashMap = new HashMap();
        hashMap.put(RecommendFragment.key_video_id, item.f10000id);
        Unit unit = Unit.INSTANCE;
        this.delJob = C0917a.m221e(C0917a.f372a, "video/delWork", Object.class, hashMap, new Function1<Object, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.medialib.child.WorksListFragment$delWorks$2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Object obj) {
                invoke2(obj);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable Object obj) {
                WorksListFragment.this.hideLoadingDialog();
                C2354n.m2409L1("删除成功");
                WorksListFragment.this.getAdapter().remove((BaseQuickAdapter<WorksBean, BaseViewHolder>) item);
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.medialib.child.WorksListFragment$delWorks$3
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
                WorksListFragment.this.hideLoadingDialog();
            }
        }, false, false, null, false, 480);
    }

    public static /* synthetic */ void delWorks$default(WorksListFragment worksListFragment, WorksBean worksBean, boolean z, int i2, Object obj) {
        if ((i2 & 2) != 0) {
            z = true;
        }
        worksListFragment.delWorks(worksBean, z);
    }

    private final HashMap<String, String> getBody() {
        return (HashMap) this.body.getValue();
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment, com.jbzd.media.movecartoons.core.MyThemeFragment, com.qunidayede.supportlibrary.core.view.BaseThemeFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    @Nullable
    public RecyclerView.ItemDecoration getItemDecoration() {
        return new ItemDecorationV(C2354n.m2425R(requireContext(), 10.0f), C2354n.m2425R(requireContext(), 20.0f));
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public int getItemLayoutId() {
        return R.layout.item_works;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment, androidx.fragment.app.Fragment
    public void onDestroyView() {
        super.onDestroyView();
        cancelJob(this.delJob);
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public void onItemChildClick(@NotNull BaseQuickAdapter<WorksBean, BaseViewHolder> adapter, @NotNull View view, int position) {
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
        super.onItemChildClick(adapter, view, position);
        final WorksBean worksBean = adapter.getData().get(position);
        if (view.getId() == R.id.tv_more) {
            new HistoryBottomDialog("删除", new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.medialib.child.WorksListFragment$onItemChildClick$1
                /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                {
                    super(0);
                }

                @Override // kotlin.jvm.functions.Function0
                public /* bridge */ /* synthetic */ Unit invoke() {
                    invoke2();
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2() {
                    WorksListFragment.this.delWorks(worksBean, true);
                }
            }).show(getChildFragmentManager(), "WorksManagerBottomDialogItem");
        }
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public void registerItemChildEvent() {
        registerItemChildClick(R.id.tv_more);
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    @Nullable
    public InterfaceC3053d1 request() {
        getBody().put("page", String.valueOf(getCurrentPage()));
        return C0917a.m222f(C0917a.f372a, "video/works", WorksBean.class, getBody(), new Function1<List<? extends WorksBean>, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.medialib.child.WorksListFragment$request$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(List<? extends WorksBean> list) {
                invoke2(list);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable List<? extends WorksBean> list) {
                WorksListFragment.this.didRequestComplete(list);
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.medialib.child.WorksListFragment$request$2
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
                WorksListFragment.this.didRequestError();
            }
        }, false, false, null, false, 480);
    }

    public final void updateCanvas(@Nullable String canvas) {
        HashMap<String, String> body = getBody();
        if (canvas == null) {
            canvas = "";
        }
        body.put("canvas", canvas);
        reset();
    }

    public final void updateStatus(@Nullable String status) {
        HashMap<String, String> body = getBody();
        if (status == null) {
            status = "";
        }
        body.put(NotificationCompat.CATEGORY_STATUS, status);
        reset();
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public void bindItem(@NotNull BaseViewHolder helper, @NotNull WorksBean item) {
        Intrinsics.checkNotNullParameter(helper, "helper");
        Intrinsics.checkNotNullParameter(item, "item");
        ImageView view = (ImageView) helper.m3912b(R.id.iv_img);
        if (item.isLong()) {
            view.setScaleType(ImageView.ScaleType.CENTER_CROP);
        } else {
            view.setScaleType(ImageView.ScaleType.FIT_CENTER);
        }
        C2852c m2455a2 = C2354n.m2455a2(requireContext());
        String str = item.img_x;
        if (str == null) {
            str = "";
        }
        C1558h mo770c = m2455a2.mo770c();
        mo770c.mo763X(str);
        ((C2851b) mo770c).m3295i0().m757R(view);
        Intrinsics.checkNotNullParameter(view, "view");
        view.setOutlineProvider(new C0859m0(5.0d));
        view.setClipToOutline(true);
        String str2 = item.money;
        if (str2 == null) {
            str2 = "";
        }
        helper.m3919i(R.id.itv_price, str2);
        helper.m3916f(R.id.rl_price, !item.getIsMoneyVideo());
        helper.m3916f(R.id.tv_freeFlag, true ^ item.getIsFreeVideo());
        String str3 = item.name;
        if (str3 == null) {
            str3 = "";
        }
        helper.m3919i(R.id.tv_name, str3);
        String str4 = item.date;
        if (str4 == null) {
            str4 = "";
        }
        helper.m3919i(R.id.tv_date, str4);
        String str5 = item.duration;
        helper.m3919i(R.id.itv_duration, str5 != null ? str5 : "");
        helper.m3919i(R.id.tv_reason, item.getStatusTxt());
    }
}
