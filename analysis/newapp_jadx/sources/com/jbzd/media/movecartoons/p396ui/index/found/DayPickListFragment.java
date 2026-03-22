package com.jbzd.media.movecartoons.p396ui.index.found;

import android.view.View;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.jbzd.media.movecartoons.bean.response.FoundPickBean;
import com.jbzd.media.movecartoons.bean.response.HomeBlockBean;
import com.jbzd.media.movecartoons.core.BaseListFragment;
import com.jbzd.media.movecartoons.p396ui.index.found.DayPickListFragment;
import com.jbzd.media.movecartoons.p396ui.index.found.child.DayPickStyleAdapter;
import com.jbzd.media.movecartoons.p396ui.index.home.HomeDataHelper;
import com.jbzd.media.movecartoons.view.XDividerItemDecoration;
import com.qnmd.adnnm.da0yzo.R;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
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
import p005b.p006a.p007a.p008a.p017r.C0917a;
import p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d;
import p379c.p380a.InterfaceC3053d1;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000T\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0010\u000b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\n\u0018\u0000 %2\b\u0012\u0004\u0012\u00020\u00020\u0001:\u0001%B\u0007¢\u0006\u0004\b#\u0010$J+\u0010\u0006\u001a\u001e\u0012\u0004\u0012\u00020\u0004\u0012\u0004\u0012\u00020\u00040\u0003j\u000e\u0012\u0004\u0012\u00020\u0004\u0012\u0004\u0012\u00020\u0004`\u0005H\u0016¢\u0006\u0004\b\u0006\u0010\u0007J\u000f\u0010\b\u001a\u00020\u0004H\u0016¢\u0006\u0004\b\b\u0010\tJ\u000f\u0010\u000b\u001a\u00020\nH\u0016¢\u0006\u0004\b\u000b\u0010\fJ\u000f\u0010\u000e\u001a\u00020\rH\u0016¢\u0006\u0004\b\u000e\u0010\u000fJ\u001f\u0010\u0014\u001a\u00020\u00132\u0006\u0010\u0011\u001a\u00020\u00102\u0006\u0010\u0012\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0014\u0010\u0015J\u0011\u0010\u0017\u001a\u0004\u0018\u00010\u0016H\u0016¢\u0006\u0004\b\u0017\u0010\u0018J\u000f\u0010\u001a\u001a\u00020\u0019H\u0016¢\u0006\u0004\b\u001a\u0010\u001bJ\u0011\u0010\u001d\u001a\u0004\u0018\u00010\u001cH\u0016¢\u0006\u0004\b\u001d\u0010\u001eR9\u0010\"\u001a\u001e\u0012\u0004\u0012\u00020\u0004\u0012\u0004\u0012\u00020\u00040\u0003j\u000e\u0012\u0004\u0012\u00020\u0004\u0012\u0004\u0012\u00020\u0004`\u00058F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u001f\u0010 \u001a\u0004\b!\u0010\u0007¨\u0006&"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/found/DayPickListFragment;", "Lcom/jbzd/media/movecartoons/core/BaseListFragment;", "Lcom/jbzd/media/movecartoons/bean/response/FoundPickBean;", "Ljava/util/HashMap;", "", "Lkotlin/collections/HashMap;", "getRequestVideoBody", "()Ljava/util/HashMap;", "getRequestUrl", "()Ljava/lang/String;", "", "getItemLayoutId", "()I", "", "getRefreshEnable", "()Z", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "helper", "item", "", "bindItem", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lcom/jbzd/media/movecartoons/bean/response/FoundPickBean;)V", "Lc/a/d1;", "request", "()Lc/a/d1;", "Landroidx/recyclerview/widget/RecyclerView$LayoutManager;", "getLayoutManager", "()Landroidx/recyclerview/widget/RecyclerView$LayoutManager;", "Landroidx/recyclerview/widget/RecyclerView$ItemDecoration;", "getItemDecoration", "()Landroidx/recyclerview/widget/RecyclerView$ItemDecoration;", "requestRoomParameter$delegate", "Lkotlin/Lazy;", "getRequestRoomParameter", "requestRoomParameter", "<init>", "()V", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class DayPickListFragment extends BaseListFragment<FoundPickBean> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    /* renamed from: requestRoomParameter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy requestRoomParameter = LazyKt__LazyJVMKt.lazy(new Function0<HashMap<String, String>>() { // from class: com.jbzd.media.movecartoons.ui.index.found.DayPickListFragment$requestRoomParameter$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final HashMap<String, String> invoke() {
            return DayPickListFragment.this.getRequestVideoBody();
        }
    });

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0010\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0005\u0010\u0006J\r\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0003\u0010\u0004¨\u0006\u0007"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/found/DayPickListFragment$Companion;", "", "Lcom/jbzd/media/movecartoons/ui/index/found/DayPickListFragment;", "newInstance", "()Lcom/jbzd/media/movecartoons/ui/index/found/DayPickListFragment;", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final DayPickListFragment newInstance() {
            return new DayPickListFragment();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindItem$lambda-2$lambda-1$lambda-0, reason: not valid java name */
    public static final void m5820bindItem$lambda2$lambda1$lambda0(BaseQuickAdapter adapter, View view, int i2) {
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment, com.jbzd.media.movecartoons.core.MyThemeFragment, com.qunidayede.supportlibrary.core.view.BaseThemeFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    @Nullable
    public RecyclerView.ItemDecoration getItemDecoration() {
        XDividerItemDecoration xDividerItemDecoration = new XDividerItemDecoration(getContext(), 1);
        xDividerItemDecoration.setDrawable(getResources().getDrawable(R.drawable.divider_line_find));
        return xDividerItemDecoration;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public int getItemLayoutId() {
        return R.layout.found_block_day_select;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    @NotNull
    public RecyclerView.LayoutManager getLayoutManager() {
        return new LinearLayoutManager(requireContext(), 1, false);
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public boolean getRefreshEnable() {
        return false;
    }

    @NotNull
    public final HashMap<String, String> getRequestRoomParameter() {
        return (HashMap) this.requestRoomParameter.getValue();
    }

    @NotNull
    public String getRequestUrl() {
        return "find/pick";
    }

    @NotNull
    public HashMap<String, String> getRequestVideoBody() {
        return new HashMap<>();
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    @Nullable
    public InterfaceC3053d1 request() {
        getRequestRoomParameter().put("page", String.valueOf(getCurrentPage()));
        return C0917a.m222f(C0917a.f372a, getRequestUrl(), FoundPickBean.class, getRequestRoomParameter(), new Function1<List<? extends FoundPickBean>, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.found.DayPickListFragment$request$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(List<? extends FoundPickBean> list) {
                invoke2(list);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable List<? extends FoundPickBean> list) {
                DayPickListFragment.this.didRequestComplete(list);
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.found.DayPickListFragment$request$2
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
                DayPickListFragment.this.didRequestError();
            }
        }, false, false, null, false, 480);
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public void bindItem(@NotNull BaseViewHolder helper, @NotNull FoundPickBean item) {
        Intrinsics.checkNotNullParameter(helper, "helper");
        Intrinsics.checkNotNullParameter(item, "item");
        String str = item.desc;
        if (str == null) {
            str = "";
        }
        helper.m3919i(R.id.tv_findTitle, str);
        ArrayList<HomeBlockBean> convertToPickList = HomeDataHelper.INSTANCE.convertToPickList(item);
        RecyclerView recyclerView = (RecyclerView) helper.m3912b(R.id.rv_findStyle);
        recyclerView.setTag(convertToPickList);
        recyclerView.setNestedScrollingEnabled(false);
        RecyclerView.Adapter adapter = recyclerView.getAdapter();
        RecyclerView.Adapter adapter2 = adapter;
        if (adapter == null) {
            recyclerView.setLayoutManager(new LinearLayoutManager(requireContext(), 1, false));
            DayPickStyleAdapter dayPickStyleAdapter = new DayPickStyleAdapter();
            dayPickStyleAdapter.setOnItemClickListener(new InterfaceC1304d() { // from class: b.a.a.a.t.g.j.d
                @Override // p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d
                public final void onItemClick(BaseQuickAdapter baseQuickAdapter, View view, int i2) {
                    DayPickListFragment.m5820bindItem$lambda2$lambda1$lambda0(baseQuickAdapter, view, i2);
                }
            });
            recyclerView.setAdapter(dayPickStyleAdapter);
            adapter2 = dayPickStyleAdapter;
        }
        ((DayPickStyleAdapter) adapter2).setNewData(convertToPickList);
    }
}
