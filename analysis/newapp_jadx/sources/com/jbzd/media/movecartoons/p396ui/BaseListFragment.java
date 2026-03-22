package com.jbzd.media.movecartoons.p396ui;

import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.view.View;
import android.view.ViewGroup;
import androidx.appcompat.widget.AppCompatButton;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.core.content.ContextCompat;
import androidx.exifinterface.media.ExifInterface;
import androidx.recyclerview.widget.RecyclerView;
import com.drake.brv.BindingAdapter;
import com.drake.brv.DefaultDecoration;
import com.drake.brv.PageRefreshLayout;
import com.drake.brv.annotaion.DividerOrientation;
import com.drake.statelayout.StateLayout;
import com.jbzd.media.movecartoons.databinding.ActPageBinding;
import com.qunidayede.supportlibrary.core.view.BaseBindingFragment;
import java.io.Serializable;
import java.util.List;
import java.util.Objects;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.functions.Function3;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p327w.p330b.p331b.p334e.InterfaceC2846i;
import p379c.p380a.p383b2.InterfaceC3006b;
import p403d.p404a.p405a.p407b.p408a.C4195m;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000N\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u000b\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\u0010!\n\u0002\b\b\b&\u0018\u0000 )*\u0004\b\u0000\u0010\u00012\b\u0012\u0004\u0012\u00020\u00030\u0002:\u0001)B\u0007¢\u0006\u0004\b(\u0010\nJ\u0017\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0005\u001a\u00020\u0004H\u0002¢\u0006\u0004\b\u0007\u0010\bJ\u000f\u0010\t\u001a\u00020\u0006H\u0016¢\u0006\u0004\b\t\u0010\nJ\u000f\u0010\u000b\u001a\u00020\u0006H\u0016¢\u0006\u0004\b\u000b\u0010\nJ\u001f\u0010\u000e\u001a\u00020\u00062\u0006\u0010\u0005\u001a\u00020\u00042\u0006\u0010\r\u001a\u00020\fH&¢\u0006\u0004\b\u000e\u0010\u000fJ\u0017\u0010\u0010\u001a\u00020\u00062\u0006\u0010\u0005\u001a\u00020\u0004H\u0016¢\u0006\u0004\b\u0010\u0010\bJ'\u0010\u0015\u001a\u00020\u00062\u0006\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0012\u001a\u00020\u00112\u0006\u0010\u0014\u001a\u00020\u0013H\u0016¢\u0006\u0004\b\u0015\u0010\u0016J#\u0010\u001a\u001a\u00020\u00062\n\u0010\u0018\u001a\u00060\u0017R\u00020\u00042\u0006\u0010\u0019\u001a\u00028\u0000H\u0016¢\u0006\u0004\b\u001a\u0010\u001bJ\u0017\u0010\u001e\u001a\u00020\u00062\u0006\u0010\u001d\u001a\u00020\u001cH\u0016¢\u0006\u0004\b\u001e\u0010\u001fJ#\u0010#\u001a\u000e\u0012\n\u0012\b\u0012\u0004\u0012\u00028\u00000\"0!2\u0006\u0010 \u001a\u00020\u0011H&¢\u0006\u0004\b#\u0010$J\u000f\u0010%\u001a\u0004\u0018\u00010\u0004¢\u0006\u0004\b%\u0010&J\r\u0010'\u001a\u00020\u0006¢\u0006\u0004\b'\u0010\n¨\u0006*"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/BaseListFragment;", ExifInterface.GPS_DIRECTION_TRUE, "Lcom/qunidayede/supportlibrary/core/view/BaseBindingFragment;", "Lcom/jbzd/media/movecartoons/databinding/ActPageBinding;", "Lcom/drake/brv/BindingAdapter;", "adapter", "", "onToggleChange", "(Lcom/drake/brv/BindingAdapter;)V", "initViews", "()V", "initEvents", "Landroidx/recyclerview/widget/RecyclerView;", "rv", "addItemListType", "(Lcom/drake/brv/BindingAdapter;Landroidx/recyclerview/widget/RecyclerView;)V", "onViewClick", "", "position", "", "checked", "onItemCheck", "(Lcom/drake/brv/BindingAdapter;IZ)V", "Lcom/drake/brv/BindingAdapter$BindingViewHolder;", "vh", "data", "onDataBinding", "(Lcom/drake/brv/BindingAdapter$BindingViewHolder;Ljava/lang/Object;)V", "Landroid/view/View;", "view", "onHandleChoice", "(Landroid/view/View;)V", "page", "Lc/a/b2/b;", "", "initFlow", "(I)Lc/a/b2/b;", "getAdapter", "()Lcom/drake/brv/BindingAdapter;", "toggle", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public abstract class BaseListFragment<T> extends BaseBindingFragment<ActPageBinding> {

    @NotNull
    public static final String KEY_DIVIDER_RES = "KEY_DIVIDER_RES";

    @NotNull
    public static final String KEY_DIVIDER_SPACE = "KEY_DIVIDER_SPACE";

    @NotNull
    public static final String KEY_EXTRA = "KEY_EXTRA";

    @NotNull
    public static final String KEY_MARGIN = "KEY_MARGIN";

    @NotNull
    public static final String KEY_ORIENTATION = "KEY_ORIENTATION";

    @NotNull
    public static final String KEY_REQUEST_URL = "KEY_REQUEST_URL";

    @NotNull
    public static final String KEY_REVERSE_LAYOUT = "KEY_REVERSE_LAYOUT";

    @NotNull
    public static final String KEY_SPAN_COUNT = "KEY_SPAN_COUNT";

    /* JADX INFO: Access modifiers changed from: private */
    public final void onToggleChange(BindingAdapter adapter) {
        ConstraintLayout constraintLayout = getBodyBinding().listToggleModel;
        Intrinsics.checkNotNullExpressionValue(constraintLayout, "bodyBinding.listToggleModel");
        constraintLayout.setVisibility(adapter.f8922x ? 0 : 8);
        if (adapter.f8922x) {
            return;
        }
        adapter.m3926b(false);
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    public abstract void addItemListType(@NotNull BindingAdapter adapter, @NotNull RecyclerView rv);

    @Nullable
    public final BindingAdapter getAdapter() {
        RecyclerView.Adapter adapter = getBodyBinding().list.getAdapter();
        if (adapter instanceof BindingAdapter) {
            return (BindingAdapter) adapter;
        }
        return null;
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public void initEvents() {
        StateLayout stateLayout;
        PageRefreshLayout pageRefreshLayout = getBodyBinding().pager;
        pageRefreshLayout.setIndex(1);
        Intrinsics.checkNotNullExpressionValue(pageRefreshLayout, "");
        if (!pageRefreshLayout.f8961h1 || (stateLayout = pageRefreshLayout.f8948U0) == null) {
            return;
        }
        StateLayout.m3994g(stateLayout, null, false, true, 2);
    }

    @NotNull
    public abstract InterfaceC3006b<List<T>> initFlow(int page);

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public void initViews() {
        bodyBinding(new Function1<ActPageBinding, Unit>(this) { // from class: com.jbzd.media.movecartoons.ui.BaseListFragment$initViews$1
            public final /* synthetic */ BaseListFragment<T> this$0;

            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
                this.this$0 = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ActPageBinding actPageBinding) {
                invoke2(actPageBinding);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull final ActPageBinding bodyBinding) {
                String str;
                Intrinsics.checkNotNullParameter(bodyBinding, "$this$bodyBinding");
                Bundle arguments = this.this$0.getArguments();
                Serializable serializable = arguments == null ? null : arguments.getSerializable(BaseListFragment.KEY_ORIENTATION);
                final DividerOrientation dividerOrientation = serializable instanceof DividerOrientation ? (DividerOrientation) serializable : null;
                Bundle arguments2 = this.this$0.getArguments();
                int i2 = arguments2 == null ? 1 : arguments2.getInt(BaseListFragment.KEY_SPAN_COUNT);
                Bundle arguments3 = this.this$0.getArguments();
                boolean z = arguments3 == null ? false : arguments3.getBoolean(BaseListFragment.KEY_REVERSE_LAYOUT);
                Bundle arguments4 = this.this$0.getArguments();
                final int i3 = arguments4 == null ? 0 : arguments4.getInt(BaseListFragment.KEY_DIVIDER_SPACE);
                Bundle arguments5 = this.this$0.getArguments();
                final int i4 = arguments5 == null ? -1 : arguments5.getInt(BaseListFragment.KEY_DIVIDER_RES);
                Bundle arguments6 = this.this$0.getArguments();
                int i5 = arguments6 == null ? 0 : arguments6.getInt(BaseListFragment.KEY_MARGIN);
                if (dividerOrientation == DividerOrientation.GRID) {
                    RecyclerView list = bodyBinding.list;
                    Intrinsics.checkNotNullExpressionValue(list, "list");
                    C4195m.m4821n0(list, i2, 0, false, false, 14);
                    str = "list";
                } else {
                    int i6 = dividerOrientation == DividerOrientation.HORIZONTAL ? 0 : 1;
                    RecyclerView list2 = bodyBinding.list;
                    Intrinsics.checkNotNullExpressionValue(list2, "list");
                    str = "list";
                    C4195m.m4835u0(list2, i6, z, false, false, 12);
                }
                if (i3 > 0 || i4 != -1) {
                    RecyclerView recyclerView = bodyBinding.list;
                    Intrinsics.checkNotNullExpressionValue(recyclerView, str);
                    C4195m.m4783P(recyclerView, new Function1<DefaultDecoration, Unit>() { // from class: com.jbzd.media.movecartoons.ui.BaseListFragment$initViews$1.1
                        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                        {
                            super(1);
                        }

                        @Override // kotlin.jvm.functions.Function1
                        public /* bridge */ /* synthetic */ Unit invoke(DefaultDecoration defaultDecoration) {
                            invoke2(defaultDecoration);
                            return Unit.INSTANCE;
                        }

                        /* renamed from: invoke, reason: avoid collision after fix types in other method */
                        public final void invoke2(@NotNull DefaultDecoration divider) {
                            Intrinsics.checkNotNullParameter(divider, "$this$divider");
                            int i7 = i3;
                            if (i7 > 0) {
                                DefaultDecoration.m3943c(divider, i7, false, 2);
                            } else {
                                Drawable drawable = ContextCompat.getDrawable(divider.f8938a, i4);
                                if (drawable == null) {
                                    throw new IllegalArgumentException("Drawable cannot be find");
                                }
                                divider.f8941d = drawable;
                            }
                            DividerOrientation dividerOrientation2 = dividerOrientation;
                            if (dividerOrientation2 == null) {
                                dividerOrientation2 = DividerOrientation.VERTICAL;
                            }
                            divider.m3946d(dividerOrientation2);
                        }
                    });
                }
                if (i5 != 0) {
                    RecyclerView recyclerView2 = bodyBinding.list;
                    Intrinsics.checkNotNullExpressionValue(recyclerView2, str);
                    ViewGroup.LayoutParams layoutParams = recyclerView2.getLayoutParams();
                    Objects.requireNonNull(layoutParams, "null cannot be cast to non-null type android.view.ViewGroup.LayoutParams");
                    ViewGroup.MarginLayoutParams marginLayoutParams = (ViewGroup.MarginLayoutParams) layoutParams;
                    marginLayoutParams.leftMargin = i5;
                    marginLayoutParams.rightMargin = i5;
                    recyclerView2.setLayoutParams(layoutParams);
                }
                RecyclerView recyclerView3 = bodyBinding.list;
                Intrinsics.checkNotNullExpressionValue(recyclerView3, str);
                final BaseListFragment<T> baseListFragment = this.this$0;
                C4195m.m4774J0(recyclerView3, new Function2<BindingAdapter, RecyclerView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.BaseListFragment$initViews$1.3
                    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                    {
                        super(2);
                    }

                    @Override // kotlin.jvm.functions.Function2
                    public /* bridge */ /* synthetic */ Unit invoke(BindingAdapter bindingAdapter, RecyclerView recyclerView4) {
                        invoke2(bindingAdapter, recyclerView4);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@NotNull final BindingAdapter setup, @NotNull RecyclerView it) {
                        Intrinsics.checkNotNullParameter(setup, "$this$setup");
                        Intrinsics.checkNotNullParameter(it, "it");
                        baseListFragment.addItemListType(setup, it);
                        final BaseListFragment<T> baseListFragment2 = baseListFragment;
                        setup.m3935l(new Function1<BindingAdapter.BindingViewHolder, Unit>() { // from class: com.jbzd.media.movecartoons.ui.BaseListFragment.initViews.1.3.1
                            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                            {
                                super(1);
                            }

                            @Override // kotlin.jvm.functions.Function1
                            public /* bridge */ /* synthetic */ Unit invoke(BindingAdapter.BindingViewHolder bindingViewHolder) {
                                invoke2(bindingViewHolder);
                                return Unit.INSTANCE;
                            }

                            /* renamed from: invoke, reason: avoid collision after fix types in other method */
                            public final void invoke2(@NotNull BindingAdapter.BindingViewHolder onBind) {
                                Intrinsics.checkNotNullParameter(onBind, "$this$onBind");
                                baseListFragment2.onDataBinding(onBind, onBind.m3942b());
                            }
                        });
                        baseListFragment.onViewClick(setup);
                        final BaseListFragment<T> baseListFragment3 = baseListFragment;
                        final ActPageBinding actPageBinding = bodyBinding;
                        setup.m3936m(new Function3<Integer, Boolean, Boolean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.BaseListFragment.initViews.1.3.2
                            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                            {
                                super(3);
                            }

                            @Override // kotlin.jvm.functions.Function3
                            public /* bridge */ /* synthetic */ Unit invoke(Integer num, Boolean bool, Boolean bool2) {
                                invoke(num.intValue(), bool.booleanValue(), bool2.booleanValue());
                                return Unit.INSTANCE;
                            }

                            public final void invoke(int i7, boolean z2, boolean z3) {
                                baseListFragment3.onItemCheck(setup, i7, z2);
                                actPageBinding.toggleChoiceModel.setChecked(z3);
                                actPageBinding.btnChoiceModel.setEnabled(setup.f8923y.size() != 0);
                            }
                        });
                        final BaseListFragment<T> baseListFragment4 = baseListFragment;
                        Function3<Integer, Boolean, Boolean, Unit> block = new Function3<Integer, Boolean, Boolean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.BaseListFragment.initViews.1.3.3
                            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                            {
                                super(3);
                            }

                            @Override // kotlin.jvm.functions.Function3
                            public /* bridge */ /* synthetic */ Unit invoke(Integer num, Boolean bool, Boolean bool2) {
                                invoke(num.intValue(), bool.booleanValue(), bool2.booleanValue());
                                return Unit.INSTANCE;
                            }

                            public final void invoke(int i7, boolean z2, boolean z3) {
                                baseListFragment4.onToggleChange(setup);
                            }
                        };
                        Intrinsics.checkNotNullParameter(block, "block");
                        setup.f8907i = block;
                    }
                });
                PageRefreshLayout pageRefreshLayout = bodyBinding.pager;
                final BaseListFragment<T> baseListFragment2 = this.this$0;
                pageRefreshLayout.m3954D(new Function1<PageRefreshLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.BaseListFragment$initViews$1.4
                    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                    {
                        super(1);
                    }

                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(PageRefreshLayout pageRefreshLayout2) {
                        invoke2(pageRefreshLayout2);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@NotNull PageRefreshLayout onRefresh) {
                        Intrinsics.checkNotNullParameter(onRefresh, "$this$onRefresh");
                        InterfaceC3006b initFlow = baseListFragment2.initFlow(onRefresh.getF8947T0());
                        InterfaceC2846i interfaceC2846i = baseListFragment2;
                        PageRefreshLayout pager = bodyBinding.pager;
                        Intrinsics.checkNotNullExpressionValue(pager, "pager");
                        C2354n.m2447Y0(initFlow, interfaceC2846i, pager, null, 4);
                    }
                });
                AppCompatButton appCompatButton = bodyBinding.btnChoiceModel;
                final BaseListFragment<T> baseListFragment3 = this.this$0;
                C2354n.m2374A(appCompatButton, 0L, new Function1<AppCompatButton, Unit>() { // from class: com.jbzd.media.movecartoons.ui.BaseListFragment$initViews$1.5
                    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                    {
                        super(1);
                    }

                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(AppCompatButton appCompatButton2) {
                        invoke2(appCompatButton2);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@NotNull AppCompatButton it) {
                        Intrinsics.checkNotNullParameter(it, "it");
                        baseListFragment3.onHandleChoice(it);
                    }
                }, 1);
            }
        });
    }

    public void onDataBinding(@NotNull BindingAdapter.BindingViewHolder vh, T data) {
        Intrinsics.checkNotNullParameter(vh, "vh");
    }

    public void onHandleChoice(@NotNull View view) {
        Intrinsics.checkNotNullParameter(view, "view");
    }

    public void onItemCheck(@NotNull BindingAdapter adapter, int position, boolean checked) {
        Intrinsics.checkNotNullParameter(adapter, "adapter");
    }

    public void onViewClick(@NotNull BindingAdapter adapter) {
        Intrinsics.checkNotNullParameter(adapter, "adapter");
    }

    public final void toggle() {
        Function3<? super Integer, ? super Boolean, ? super Boolean, Unit> function3;
        RecyclerView.Adapter adapter = getBodyBinding().list.getAdapter();
        if (adapter == null || !(adapter instanceof BindingAdapter)) {
            return;
        }
        BindingAdapter bindingAdapter = (BindingAdapter) adapter;
        if (bindingAdapter.m3931h() == 0 || (function3 = bindingAdapter.f8907i) == null) {
            return;
        }
        bindingAdapter.f8922x = !bindingAdapter.f8922x;
        int i2 = 0;
        int itemCount = bindingAdapter.getItemCount();
        while (i2 < itemCount) {
            int i3 = i2 + 1;
            if (i2 != bindingAdapter.getItemCount() - 1) {
                function3.invoke(Integer.valueOf(i2), Boolean.valueOf(bindingAdapter.f8922x), Boolean.FALSE);
            } else {
                function3.invoke(Integer.valueOf(i2), Boolean.valueOf(bindingAdapter.f8922x), Boolean.TRUE);
            }
            i2 = i3;
        }
    }
}
