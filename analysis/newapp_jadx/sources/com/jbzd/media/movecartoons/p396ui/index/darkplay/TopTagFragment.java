package com.jbzd.media.movecartoons.p396ui.index.darkplay;

import android.os.Bundle;
import android.view.View;
import android.widget.ImageView;
import androidx.fragment.app.Fragment;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import androidx.swiperefreshlayout.widget.SwipeRefreshLayout;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.jbzd.media.movecartoons.R$id;
import com.jbzd.media.movecartoons.bean.response.DarkPlayTagBean;
import com.jbzd.media.movecartoons.core.BaseListFragment;
import com.qnmd.adnnm.da0yzo.R;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
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
import p005b.p067b.p068a.p069a.p070a.p078m.C1318f;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.InterfaceC3053d1;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000P\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u000b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\b\n\u0002\u0010!\n\u0002\b\u000f\u0018\u0000 02\b\u0012\u0004\u0012\u00020\u00020\u0001:\u00010B\u0007¢\u0006\u0004\b.\u0010/J\u000f\u0010\u0004\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u0004\u0010\u0005J\u001f\u0010\n\u001a\u00020\t2\u0006\u0010\u0007\u001a\u00020\u00062\u0006\u0010\b\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\n\u0010\u000bJ\u000f\u0010\r\u001a\u00020\fH\u0016¢\u0006\u0004\b\r\u0010\u000eJ\u000f\u0010\u0010\u001a\u00020\u000fH\u0016¢\u0006\u0004\b\u0010\u0010\u0011J\u000f\u0010\u0013\u001a\u00020\u0012H\u0016¢\u0006\u0004\b\u0013\u0010\u0014J\u0015\u0010\u0016\u001a\u00020\t2\u0006\u0010\u0015\u001a\u00020\u000f¢\u0006\u0004\b\u0016\u0010\u0017R?\u0010\u001c\u001a\u001f\u0012\u0013\u0012\u00110\u0002¢\u0006\f\b\u0019\u0012\b\b\u001a\u0012\u0004\b\b(\u001b\u0012\u0004\u0012\u00020\t\u0018\u00010\u00188\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\u001c\u0010\u001d\u001a\u0004\b\u001e\u0010\u001f\"\u0004\b \u0010!R(\u0010#\u001a\b\u0012\u0004\u0012\u00020\u00020\"8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b#\u0010$\u001a\u0004\b%\u0010&\"\u0004\b'\u0010(R\"\u0010)\u001a\u00020\u00038\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b)\u0010*\u001a\u0004\b+\u0010\u0005\"\u0004\b,\u0010-¨\u00061"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/darkplay/TopTagFragment;", "Lcom/jbzd/media/movecartoons/core/BaseListFragment;", "Lcom/jbzd/media/movecartoons/bean/response/DarkPlayTagBean;", "", "getItemLayoutId", "()I", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "helper", "item", "", "bindItem", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lcom/jbzd/media/movecartoons/bean/response/DarkPlayTagBean;)V", "Landroidx/recyclerview/widget/RecyclerView$LayoutManager;", "getLayoutManager", "()Landroidx/recyclerview/widget/RecyclerView$LayoutManager;", "", "getRefreshEnable", "()Z", "Lc/a/d1;", "request", "()Lc/a/d1;", "boolean", "downloadFinish", "(Z)V", "Lkotlin/Function1;", "Lkotlin/ParameterName;", "name", "bean", "callBack", "Lkotlin/jvm/functions/Function1;", "getCallBack", "()Lkotlin/jvm/functions/Function1;", "setCallBack", "(Lkotlin/jvm/functions/Function1;)V", "", "list", "Ljava/util/List;", "getList", "()Ljava/util/List;", "setList", "(Ljava/util/List;)V", "mId", "I", "getMId", "setMId", "(I)V", "<init>", "()V", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class TopTagFragment extends BaseListFragment<DarkPlayTagBean> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    /* renamed from: ID */
    @NotNull
    private static final String f10114ID = "id";

    @Nullable
    private Function1<? super DarkPlayTagBean, Unit> callBack;

    @NotNull
    private List<DarkPlayTagBean> list = new ArrayList();
    private int mId;

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0016\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0007\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\t\u0010\nJ\u0017\u0010\u0005\u001a\u00020\u00042\b\b\u0002\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0005\u0010\u0006R\u0016\u0010\u0007\u001a\u00020\u00028\u0002@\u0002X\u0082T¢\u0006\u0006\n\u0004\b\u0007\u0010\b¨\u0006\u000b"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/darkplay/TopTagFragment$Companion;", "", "", TopTagFragment.f10114ID, "Lcom/jbzd/media/movecartoons/ui/index/darkplay/TopTagFragment;", "newInstance", "(Ljava/lang/String;)Lcom/jbzd/media/movecartoons/ui/index/darkplay/TopTagFragment;", "ID", "Ljava/lang/String;", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public static /* synthetic */ TopTagFragment newInstance$default(Companion companion, String str, int i2, Object obj) {
            if ((i2 & 1) != 0) {
                str = "";
            }
            return companion.newInstance(str);
        }

        @NotNull
        public final TopTagFragment newInstance(@NotNull String id) {
            Intrinsics.checkNotNullParameter(id, "id");
            TopTagFragment topTagFragment = new TopTagFragment();
            Bundle bundle = new Bundle();
            bundle.putString(TopTagFragment.f10114ID, id);
            Unit unit = Unit.INSTANCE;
            topTagFragment.setArguments(bundle);
            return topTagFragment;
        }
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment, com.jbzd.media.movecartoons.core.MyThemeFragment, com.qunidayede.supportlibrary.core.view.BaseThemeFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    public final void downloadFinish(boolean r5) {
        View view = getView();
        ((SwipeRefreshLayout) (view == null ? null : view.findViewById(R$id.swipeLayout))).setRefreshing(r5);
        C1318f loadMoreModule = getAdapter().getLoadMoreModule();
        if (loadMoreModule != null) {
            loadMoreModule.m330f();
        }
        C1318f loadMoreModule2 = getAdapter().getLoadMoreModule();
        if (loadMoreModule2 != null) {
            C1318f.m324h(loadMoreModule2, false, 1, null);
        }
        C1318f loadMoreModule3 = getAdapter().getLoadMoreModule();
        if (loadMoreModule3 != null) {
            loadMoreModule3.f1060i = r5;
        }
        C1318f loadMoreModule4 = getAdapter().getLoadMoreModule();
        if (loadMoreModule4 != null) {
            loadMoreModule4.f1056e = !r5;
        }
        C1318f loadMoreModule5 = getAdapter().getLoadMoreModule();
        if (loadMoreModule5 != null) {
            loadMoreModule5.m334k(r5);
        }
        Fragment parentFragment = getParentFragment();
        if (parentFragment != null) {
            View view2 = parentFragment.getView();
            r1 = (ImageView) (view2 != null ? view2.findViewById(R$id.iv_tag) : null);
        }
        if (r1 == null) {
            return;
        }
        r1.setVisibility(r5 ? 0 : 8);
    }

    @Nullable
    public final Function1<DarkPlayTagBean, Unit> getCallBack() {
        return this.callBack;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public int getItemLayoutId() {
        return R.layout.item_dark_trade_tag;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    @NotNull
    public RecyclerView.LayoutManager getLayoutManager() {
        LinearLayoutManager linearLayoutManager = new LinearLayoutManager(requireContext());
        linearLayoutManager.setOrientation(0);
        return linearLayoutManager;
    }

    @NotNull
    public final List<DarkPlayTagBean> getList() {
        return this.list;
    }

    public final int getMId() {
        return this.mId;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public boolean getRefreshEnable() {
        return false;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    @NotNull
    public InterfaceC3053d1 request() {
        getRv_content().addOnScrollListener(new RecyclerView.OnScrollListener() { // from class: com.jbzd.media.movecartoons.ui.index.darkplay.TopTagFragment$request$1
            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrolled(@NotNull RecyclerView rv, int dx, int dy) {
                Intrinsics.checkNotNullParameter(rv, "rv");
                super.onScrolled(rv, dx, dy);
                Fragment parentFragment = TopTagFragment.this.getParentFragment();
                if (parentFragment != null) {
                    View view = parentFragment.getView();
                    r4 = (ImageView) (view != null ? view.findViewById(R$id.iv_tag) : null);
                }
                if (r4 == null) {
                    return;
                }
                r4.setVisibility(rv.canScrollHorizontally(1) ? 0 : 8);
            }
        });
        HashMap hashMap = new HashMap();
        hashMap.put("all", "1");
        return C0917a.m222f(C0917a.f372a, "trade/topic", DarkPlayTagBean.class, hashMap, new Function1<List<? extends DarkPlayTagBean>, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.darkplay.TopTagFragment$request$3
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(List<? extends DarkPlayTagBean> list) {
                invoke2((List<DarkPlayTagBean>) list);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable List<DarkPlayTagBean> list) {
                if (list == null) {
                    return;
                }
                TopTagFragment topTagFragment = TopTagFragment.this;
                Function1<DarkPlayTagBean, Unit> callBack = topTagFragment.getCallBack();
                if (callBack != null) {
                    callBack.invoke(list.get(0));
                }
                topTagFragment.didRequestComplete(list);
                topTagFragment.downloadFinish(false);
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.darkplay.TopTagFragment$request$4
            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                invoke2(exc);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull Exception it) {
                Intrinsics.checkNotNullParameter(it, "it");
            }
        }, false, false, null, false, 480);
    }

    public final void setCallBack(@Nullable Function1<? super DarkPlayTagBean, Unit> function1) {
        this.callBack = function1;
    }

    public final void setList(@NotNull List<DarkPlayTagBean> list) {
        Intrinsics.checkNotNullParameter(list, "<set-?>");
        this.list = list;
    }

    public final void setMId(int i2) {
        this.mId = i2;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public void bindItem(@NotNull final BaseViewHolder helper, @NotNull final DarkPlayTagBean item) {
        Intrinsics.checkNotNullParameter(helper, "helper");
        Intrinsics.checkNotNullParameter(item, "item");
        helper.m3912b(R.id.view_up).setSelected(getMId() == helper.getAdapterPosition());
        helper.m3916f(R.id.iv_arrow_down, !r0.isSelected());
        StringBuilder sb = new StringBuilder();
        sb.append('#');
        sb.append((Object) item.getName());
        sb.append('#');
        helper.m3919i(R.id.iv_center_playicon, sb.toString());
        C2354n.m2455a2(requireContext()).m3298p(item.getImg()).m3295i0().m757R((ImageView) helper.m3912b(R.id.ivImg));
        View view = helper.itemView;
        Intrinsics.checkNotNullExpressionValue(view, "helper.itemView");
        Intrinsics.checkNotNullParameter(view, "view");
        view.setOutlineProvider(new C0859m0(2.5d));
        view.setClipToOutline(true);
        helper.m3918h(R.id.rv_tag_layout, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.darkplay.TopTagFragment$bindItem$1$1
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
                Function1<DarkPlayTagBean, Unit> callBack = TopTagFragment.this.getCallBack();
                if (callBack != null) {
                    callBack.invoke(item);
                }
                TopTagFragment.this.setMId(helper.getAdapterPosition());
                TopTagFragment.this.getAdapter().notifyDataSetChanged();
            }
        });
    }
}
