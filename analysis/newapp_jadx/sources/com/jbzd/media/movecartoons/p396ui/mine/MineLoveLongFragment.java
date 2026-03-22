package com.jbzd.media.movecartoons.p396ui.mine;

import androidx.core.app.NotificationCompat;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentViewModelLazyKt;
import androidx.lifecycle.Observer;
import androidx.lifecycle.ViewModelStore;
import androidx.lifecycle.ViewModelStoreOwner;
import com.jbzd.media.movecartoons.core.MyThemeViewModelFragment;
import com.jbzd.media.movecartoons.p396ui.mine.FavoriteHistoryListFragment;
import com.jbzd.media.movecartoons.p396ui.mine.mineViewModel.LoveViewModel;
import com.qnmd.adnnm.da0yzo.R;
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
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p327w.p330b.p331b.p335f.C2848a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000$\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\b\u0007\u0018\u0000 \u00152\b\u0012\u0004\u0012\u00020\u00020\u0001:\u0001\u0015B\u0007¢\u0006\u0004\b\u0014\u0010\bJ\u000f\u0010\u0004\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u0004\u0010\u0005J\u000f\u0010\u0007\u001a\u00020\u0006H\u0016¢\u0006\u0004\b\u0007\u0010\bJ\u000f\u0010\t\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\t\u0010\nR\u001d\u0010\u000e\u001a\u00020\u00028F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u000b\u0010\f\u001a\u0004\b\r\u0010\nR\u001d\u0010\u0013\u001a\u00020\u000f8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0010\u0010\f\u001a\u0004\b\u0011\u0010\u0012¨\u0006\u0016"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/mine/MineLoveLongFragment;", "Lcom/jbzd/media/movecartoons/core/MyThemeViewModelFragment;", "Lcom/jbzd/media/movecartoons/ui/mine/mineViewModel/LoveViewModel;", "", "getLayout", "()I", "", "initViews", "()V", "viewModelInstance", "()Lcom/jbzd/media/movecartoons/ui/mine/mineViewModel/LoveViewModel;", "viewModel$delegate", "Lkotlin/Lazy;", "getViewModel", "viewModel", "Lcom/jbzd/media/movecartoons/ui/mine/FavoriteHistoryListFragment;", "mFragment$delegate", "getMFragment", "()Lcom/jbzd/media/movecartoons/ui/mine/FavoriteHistoryListFragment;", "mFragment", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class MineLoveLongFragment extends MyThemeViewModelFragment<LoveViewModel> {
    public static Function1<? super Boolean, Unit> callBack;

    /* renamed from: mFragment$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mFragment = LazyKt__LazyJVMKt.lazy(new Function0<FavoriteHistoryListFragment>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineLoveLongFragment$mFragment$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final FavoriteHistoryListFragment invoke() {
            FavoriteHistoryListFragment.Companion companion = FavoriteHistoryListFragment.INSTANCE;
            String pageType2 = MineLoveLongFragment.INSTANCE.getPageType();
            final MineLoveLongFragment mineLoveLongFragment = MineLoveLongFragment.this;
            return companion.newInstance(pageType2, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineLoveLongFragment$mFragment$2.1
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
                    MineLoveLongFragment.this.getViewModel().getLoading().setValue(new C2848a(false, null, false, false, 14));
                }
            });
        }
    });

    /* renamed from: viewModel$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy viewModel;

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @NotNull
    private static String pageType = "";

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000,\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u000b\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0011\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u001a\u0010\u001bJ8\u0010\f\u001a\u00020\u000b2\u0006\u0010\u0003\u001a\u00020\u00022!\u0010\n\u001a\u001d\u0012\u0013\u0012\u00110\u0005¢\u0006\f\b\u0006\u0012\b\b\u0007\u0012\u0004\b\b(\b\u0012\u0004\u0012\u00020\t0\u0004¢\u0006\u0004\b\f\u0010\rR=\u0010\u000e\u001a\u001d\u0012\u0013\u0012\u00110\u0005¢\u0006\f\b\u0006\u0012\b\b\u0007\u0012\u0004\b\b(\b\u0012\u0004\u0012\u00020\t0\u00048\u0006@\u0006X\u0086.¢\u0006\u0012\n\u0004\b\u000e\u0010\u000f\u001a\u0004\b\u0010\u0010\u0011\"\u0004\b\u0012\u0010\u0013R\"\u0010\u0014\u001a\u00020\u00028\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\u0014\u0010\u0015\u001a\u0004\b\u0016\u0010\u0017\"\u0004\b\u0018\u0010\u0019¨\u0006\u001c"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/mine/MineLoveLongFragment$Companion;", "", "", "type", "Lkotlin/Function1;", "", "Lkotlin/ParameterName;", "name", "switch", "", NotificationCompat.CATEGORY_CALL, "Lcom/jbzd/media/movecartoons/ui/mine/MineLoveLongFragment;", "newInstance", "(Ljava/lang/String;Lkotlin/jvm/functions/Function1;)Lcom/jbzd/media/movecartoons/ui/mine/MineLoveLongFragment;", "callBack", "Lkotlin/jvm/functions/Function1;", "getCallBack", "()Lkotlin/jvm/functions/Function1;", "setCallBack", "(Lkotlin/jvm/functions/Function1;)V", "pageType", "Ljava/lang/String;", "getPageType", "()Ljava/lang/String;", "setPageType", "(Ljava/lang/String;)V", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final Function1<Boolean, Unit> getCallBack() {
            Function1 function1 = MineLoveLongFragment.callBack;
            if (function1 != null) {
                return function1;
            }
            Intrinsics.throwUninitializedPropertyAccessException("callBack");
            throw null;
        }

        @NotNull
        public final String getPageType() {
            return MineLoveLongFragment.pageType;
        }

        @NotNull
        public final MineLoveLongFragment newInstance(@NotNull String type, @NotNull Function1<? super Boolean, Unit> call) {
            Intrinsics.checkNotNullParameter(type, "type");
            Intrinsics.checkNotNullParameter(call, "call");
            setPageType(type);
            MineLoveLongFragment mineLoveLongFragment = new MineLoveLongFragment();
            MineLoveLongFragment.INSTANCE.setCallBack(call);
            return mineLoveLongFragment;
        }

        public final void setCallBack(@NotNull Function1<? super Boolean, Unit> function1) {
            Intrinsics.checkNotNullParameter(function1, "<set-?>");
            MineLoveLongFragment.callBack = function1;
        }

        public final void setPageType(@NotNull String str) {
            Intrinsics.checkNotNullParameter(str, "<set-?>");
            MineLoveLongFragment.pageType = str;
        }
    }

    public MineLoveLongFragment() {
        final Function0<Fragment> function0 = new Function0<Fragment>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineLoveLongFragment$special$$inlined$viewModels$default$1
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
        this.viewModel = FragmentViewModelLazyKt.createViewModelLazy(this, Reflection.getOrCreateKotlinClass(LoveViewModel.class), new Function0<ViewModelStore>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineLoveLongFragment$special$$inlined$viewModels$default$2
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

    /* JADX INFO: Access modifiers changed from: private */
    public final FavoriteHistoryListFragment getMFragment() {
        return (FavoriteHistoryListFragment) this.mFragment.getValue();
    }

    @Override // com.jbzd.media.movecartoons.core.MyThemeViewModelFragment, com.qunidayede.supportlibrary.core.view.BaseThemeViewModelFragment, com.qunidayede.supportlibrary.core.view.BaseViewModelFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public int getLayout() {
        return R.layout.frag_mine_love;
    }

    @NotNull
    public final LoveViewModel getViewModel() {
        return (LoveViewModel) this.viewModel.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public void initViews() {
        super.initViews();
        getChildFragmentManager().beginTransaction().replace(R.id.frag_content, getMFragment()).commit();
        LoveViewModel viewModel = getViewModel();
        viewModel.getHistoryUpdateSuccess().observe(this, new Observer<T>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineLoveLongFragment$initViews$lambda-4$$inlined$observe$1
            /* JADX WARN: Multi-variable type inference failed */
            @Override // androidx.lifecycle.Observer
            public final void onChanged(T t) {
                Boolean it = (Boolean) t;
                Intrinsics.checkNotNullExpressionValue(it, "it");
                if (it.booleanValue()) {
                    C2354n.m2409L1("删除成功");
                } else {
                    C2354n.m2449Z("删除失败");
                }
            }
        });
        viewModel.getMyFavCheckBoxView().observe(this, new Observer<T>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineLoveLongFragment$initViews$lambda-4$$inlined$observe$2
            /* JADX WARN: Multi-variable type inference failed */
            @Override // androidx.lifecycle.Observer
            public final void onChanged(T t) {
                FavoriteHistoryListFragment mFragment;
                FavoriteHistoryListFragment mFragment2;
                FavoriteHistoryListFragment mFragment3;
                Boolean it = (Boolean) t;
                mFragment = MineLoveLongFragment.this.getMFragment();
                Intrinsics.checkNotNullExpressionValue(it, "it");
                mFragment.setCheckBox(it.booleanValue());
                mFragment2 = MineLoveLongFragment.this.getMFragment();
                mFragment2.setCheckBoxAll(false);
                MineLoveLongFragment.INSTANCE.getCallBack().invoke(it);
                mFragment3 = MineLoveLongFragment.this.getMFragment();
                mFragment3.getAdapter().notifyDataSetChanged();
            }
        });
        viewModel.getCheckBoxAll().observe(this, new Observer<T>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineLoveLongFragment$initViews$lambda-4$$inlined$observe$3
            /* JADX WARN: Multi-variable type inference failed */
            @Override // androidx.lifecycle.Observer
            public final void onChanged(T t) {
                FavoriteHistoryListFragment mFragment;
                FavoriteHistoryListFragment mFragment2;
                FavoriteHistoryListFragment mFragment3;
                FavoriteHistoryListFragment mFragment4;
                Boolean it = (Boolean) t;
                Intrinsics.checkNotNullExpressionValue(it, "it");
                if (it.booleanValue()) {
                    mFragment4 = MineLoveLongFragment.this.getMFragment();
                    mFragment4.selectAllData();
                } else {
                    mFragment = MineLoveLongFragment.this.getMFragment();
                    mFragment.deleteAllData();
                }
                mFragment2 = MineLoveLongFragment.this.getMFragment();
                mFragment2.setCheckBoxAll(it.booleanValue());
                MineLoveLongFragment.INSTANCE.getCallBack().invoke(it);
                mFragment3 = MineLoveLongFragment.this.getMFragment();
                mFragment3.getAdapter().notifyDataSetChanged();
            }
        });
        viewModel.getCheckBoxDeleteSubmit().observe(this, new Observer<T>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineLoveLongFragment$initViews$lambda-4$$inlined$observe$4
            /* JADX WARN: Multi-variable type inference failed */
            @Override // androidx.lifecycle.Observer
            public final void onChanged(T t) {
                FavoriteHistoryListFragment mFragment;
                mFragment = MineLoveLongFragment.this.getMFragment();
                mFragment.deleteVideo(MineLoveLongFragment.pageType);
            }
        });
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseViewModelFragment
    @NotNull
    public LoveViewModel viewModelInstance() {
        return getViewModel();
    }
}
