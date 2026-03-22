package com.jbzd.media.movecartoons.p396ui.mine;

import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentViewModelLazyKt;
import androidx.lifecycle.Observer;
import androidx.lifecycle.ViewModelStore;
import androidx.lifecycle.ViewModelStoreOwner;
import com.jbzd.media.movecartoons.bean.response.VideoItemBean;
import com.jbzd.media.movecartoons.core.MyThemeViewModelFragment;
import com.jbzd.media.movecartoons.p396ui.mine.mineViewModel.TopViewModel;
import com.qnmd.adnnm.da0yzo.R;
import java.util.List;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Reflection;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000$\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\b\u0007\u0018\u0000 \u00152\b\u0012\u0004\u0012\u00020\u00020\u0001:\u0001\u0015B\u0007¢\u0006\u0004\b\u0014\u0010\bJ\u000f\u0010\u0004\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u0004\u0010\u0005J\u000f\u0010\u0007\u001a\u00020\u0006H\u0016¢\u0006\u0004\b\u0007\u0010\bJ\u000f\u0010\t\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\t\u0010\nR\u001d\u0010\u000e\u001a\u00020\u00028F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u000b\u0010\f\u001a\u0004\b\r\u0010\nR\u001d\u0010\u0013\u001a\u00020\u000f8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0010\u0010\f\u001a\u0004\b\u0011\u0010\u0012¨\u0006\u0016"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/mine/MineRecentShortFragment;", "Lcom/jbzd/media/movecartoons/core/MyThemeViewModelFragment;", "Lcom/jbzd/media/movecartoons/ui/mine/mineViewModel/TopViewModel;", "", "getLayout", "()I", "", "initViews", "()V", "viewModelInstance", "()Lcom/jbzd/media/movecartoons/ui/mine/mineViewModel/TopViewModel;", "viewModel$delegate", "Lkotlin/Lazy;", "getViewModel", "viewModel", "Lcom/jbzd/media/movecartoons/ui/mine/RemoveShortVideoListFragment;", "mFragment$delegate", "getMFragment", "()Lcom/jbzd/media/movecartoons/ui/mine/RemoveShortVideoListFragment;", "mFragment", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class MineRecentShortFragment extends MyThemeViewModelFragment<TopViewModel> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);
    public static String canvas;

    /* renamed from: mFragment$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mFragment = LazyKt__LazyJVMKt.lazy(new Function0<RemoveShortVideoListFragment>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineRecentShortFragment$mFragment$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final RemoveShortVideoListFragment invoke() {
            return RemoveShortVideoListFragment.INSTANCE.newInstance(MineRecentShortFragment.INSTANCE.getCanvas(), new Function1<List<? extends VideoItemBean>, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineRecentShortFragment$mFragment$2.1
                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(List<? extends VideoItemBean> list) {
                    invoke2(list);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(@Nullable List<? extends VideoItemBean> list) {
                }
            });
        }
    });

    /* renamed from: viewModel$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy viewModel;

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0016\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u000b\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\r\u0010\u000eJ\u0015\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0005\u0010\u0006R\"\u0010\u0007\u001a\u00020\u00028\u0006@\u0006X\u0086.¢\u0006\u0012\n\u0004\b\u0007\u0010\b\u001a\u0004\b\t\u0010\n\"\u0004\b\u000b\u0010\f¨\u0006\u000f"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/mine/MineRecentShortFragment$Companion;", "", "", "type", "Lcom/jbzd/media/movecartoons/ui/mine/MineRecentShortFragment;", "newInstance", "(Ljava/lang/String;)Lcom/jbzd/media/movecartoons/ui/mine/MineRecentShortFragment;", "canvas", "Ljava/lang/String;", "getCanvas", "()Ljava/lang/String;", "setCanvas", "(Ljava/lang/String;)V", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final String getCanvas() {
            String str = MineRecentShortFragment.canvas;
            if (str != null) {
                return str;
            }
            Intrinsics.throwUninitializedPropertyAccessException("canvas");
            throw null;
        }

        @NotNull
        public final MineRecentShortFragment newInstance(@NotNull String type) {
            Intrinsics.checkNotNullParameter(type, "type");
            MineRecentShortFragment mineRecentShortFragment = new MineRecentShortFragment();
            MineRecentShortFragment.INSTANCE.setCanvas(type);
            return mineRecentShortFragment;
        }

        public final void setCanvas(@NotNull String str) {
            Intrinsics.checkNotNullParameter(str, "<set-?>");
            MineRecentShortFragment.canvas = str;
        }
    }

    public MineRecentShortFragment() {
        final Function0<Fragment> function0 = new Function0<Fragment>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineRecentShortFragment$special$$inlined$viewModels$default$1
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final Fragment invoke() {
                return Fragment.this;
            }
        };
        this.viewModel = FragmentViewModelLazyKt.createViewModelLazy(this, Reflection.getOrCreateKotlinClass(TopViewModel.class), new Function0<ViewModelStore>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineRecentShortFragment$special$$inlined$viewModels$default$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final ViewModelStore invoke() {
                ViewModelStore viewModelStore = ((ViewModelStoreOwner) Function0.this.invoke()).getViewModelStore();
                Intrinsics.checkExpressionValueIsNotNull(viewModelStore, "ownerProducer().viewModelStore");
                return viewModelStore;
            }
        }, null);
    }

    @Override // com.jbzd.media.movecartoons.core.MyThemeViewModelFragment, com.qunidayede.supportlibrary.core.view.BaseThemeViewModelFragment, com.qunidayede.supportlibrary.core.view.BaseViewModelFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public int getLayout() {
        return R.layout.frag_mine_recent;
    }

    @NotNull
    public final RemoveShortVideoListFragment getMFragment() {
        return (RemoveShortVideoListFragment) this.mFragment.getValue();
    }

    @NotNull
    public final TopViewModel getViewModel() {
        return (TopViewModel) this.viewModel.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public void initViews() {
        super.initViews();
        getChildFragmentManager().beginTransaction().replace(R.id.frag_content, getMFragment()).commit();
        getViewModel().getHistoryUpdateSuccess().observe(this, new Observer<T>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineRecentShortFragment$initViews$lambda-1$$inlined$observe$1
            /* JADX WARN: Multi-variable type inference failed */
            @Override // androidx.lifecycle.Observer
            public final void onChanged(T t) {
                Boolean it = (Boolean) t;
                MineRecentShortFragment.this.getMFragment().refresh();
                Intrinsics.checkNotNullExpressionValue(it, "it");
                if (it.booleanValue()) {
                    C2354n.m2409L1("删除成功");
                } else {
                    C2354n.m2449Z("删除失败");
                }
            }
        });
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseViewModelFragment
    @NotNull
    public TopViewModel viewModelInstance() {
        return getViewModel();
    }
}
