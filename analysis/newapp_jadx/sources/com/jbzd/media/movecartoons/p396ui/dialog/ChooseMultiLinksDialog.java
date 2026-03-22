package com.jbzd.media.movecartoons.p396ui.dialog;

import android.app.Activity;
import android.util.DisplayMetrics;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.appcompat.widget.ActivityChooserModel;
import androidx.recyclerview.widget.RecyclerView;
import com.drake.brv.BindingAdapter;
import com.drake.brv.annotaion.DividerOrientation;
import com.jbzd.media.movecartoons.bean.response.VideoDetailBean;
import com.jbzd.media.movecartoons.p396ui.movie.MovieDetailsViewModel;
import com.qnmd.adnnm.da0yzo.R;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.CollectionsKt__CollectionsKt;
import kotlin.collections.CollectionsKt___CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.functions.Function3;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Reflection;
import org.jetbrains.annotations.NotNull;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p327w.p330b.p337d.C2861e;
import p403d.p404a.p405a.p407b.p408a.C4195m;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000L\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\n\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0010\b\n\u0002\b\u0006\u0018\u0000 52\u00020\u0001:\u00015B'\u0012\u0006\u0010*\u001a\u00020)\u0012\u0006\u0010/\u001a\u00020\"\u0012\u0006\u00101\u001a\u000200\u0012\u0006\u00102\u001a\u000200¢\u0006\u0004\b3\u00104J\u000f\u0010\u0003\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\u0003\u0010\u0004J\u001b\u0010\b\u001a\u00020\u00022\f\u0010\u0007\u001a\b\u0012\u0004\u0012\u00020\u00060\u0005¢\u0006\u0004\b\b\u0010\tJ\r\u0010\n\u001a\u00020\u0002¢\u0006\u0004\b\n\u0010\u0004J\u000f\u0010\u000b\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u000b\u0010\u0004R\u001d\u0010\u0011\u001a\u00020\f8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\r\u0010\u000e\u001a\u0004\b\u000f\u0010\u0010R(\u0010\u0012\u001a\b\u0012\u0004\u0012\u00020\u00060\u00058\u0006@\u0006X\u0086.¢\u0006\u0012\n\u0004\b\u0012\u0010\u0013\u001a\u0004\b\u0014\u0010\u0015\"\u0004\b\u0016\u0010\tR\u001d\u0010\u001b\u001a\u00020\u00178B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0018\u0010\u000e\u001a\u0004\b\u0019\u0010\u001aR%\u0010!\u001a\n \u001d*\u0004\u0018\u00010\u001c0\u001c8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u001e\u0010\u000e\u001a\u0004\b\u001f\u0010 R\"\u0010#\u001a\u00020\"8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b#\u0010$\u001a\u0004\b%\u0010&\"\u0004\b'\u0010(R\u0016\u0010*\u001a\u00020)8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b*\u0010+R\u001d\u0010.\u001a\u00020\u001c8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b,\u0010\u000e\u001a\u0004\b-\u0010 ¨\u00066"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/dialog/ChooseMultiLinksDialog;", "Lcom/jbzd/media/movecartoons/ui/dialog/StrongBottomSheetDialog;", "", "initDefaultShow", "()V", "", "Lcom/jbzd/media/movecartoons/bean/response/VideoDetailBean$MultiLinks;", "multilinks", "setLinksData", "(Ljava/util/List;)V", "init", "dismiss", "Landroidx/recyclerview/widget/RecyclerView;", "rv_multilinks_dialog$delegate", "Lkotlin/Lazy;", "getRv_multilinks_dialog", "()Landroidx/recyclerview/widget/RecyclerView;", "rv_multilinks_dialog", "multi_links", "Ljava/util/List;", "getMulti_links", "()Ljava/util/List;", "setMulti_links", "Landroid/widget/ImageView;", "iv_dismiss$delegate", "getIv_dismiss", "()Landroid/widget/ImageView;", "iv_dismiss", "Landroid/view/View;", "kotlin.jvm.PlatformType", "contentView$delegate", "getContentView", "()Landroid/view/View;", "contentView", "Lcom/jbzd/media/movecartoons/ui/movie/MovieDetailsViewModel;", "mViewModel", "Lcom/jbzd/media/movecartoons/ui/movie/MovieDetailsViewModel;", "getMViewModel", "()Lcom/jbzd/media/movecartoons/ui/movie/MovieDetailsViewModel;", "setMViewModel", "(Lcom/jbzd/media/movecartoons/ui/movie/MovieDetailsViewModel;)V", "Landroid/app/Activity;", "context", "Landroid/app/Activity;", "outside_view$delegate", "getOutside_view", "outside_view", "viewModel", "", "peekHeight", "maxHeight", "<init>", "(Landroid/app/Activity;Lcom/jbzd/media/movecartoons/ui/movie/MovieDetailsViewModel;II)V", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class ChooseMultiLinksDialog extends StrongBottomSheetDialog {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    /* renamed from: contentView$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy contentView;

    @NotNull
    private final Activity context;

    /* renamed from: iv_dismiss$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy iv_dismiss;

    @NotNull
    private MovieDetailsViewModel mViewModel;
    public List<? extends VideoDetailBean.MultiLinks> multi_links;

    /* renamed from: outside_view$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy outside_view;

    /* renamed from: rv_multilinks_dialog$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rv_multilinks_dialog;

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u001c\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\t\u0010\nJ\u001d\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0005\u001a\u00020\u0004¢\u0006\u0004\b\u0007\u0010\b¨\u0006\u000b"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/dialog/ChooseMultiLinksDialog$Companion;", "", "Landroid/app/Activity;", ActivityChooserModel.ATTRIBUTE_ACTIVITY, "Lcom/jbzd/media/movecartoons/ui/movie/MovieDetailsViewModel;", "viewModel", "Lcom/jbzd/media/movecartoons/ui/dialog/ChooseMultiLinksDialog;", "chooseMultilinks", "(Landroid/app/Activity;Lcom/jbzd/media/movecartoons/ui/movie/MovieDetailsViewModel;)Lcom/jbzd/media/movecartoons/ui/dialog/ChooseMultiLinksDialog;", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final ChooseMultiLinksDialog chooseMultilinks(@NotNull Activity activity, @NotNull MovieDetailsViewModel viewModel) {
            View findViewById;
            Intrinsics.checkNotNullParameter(activity, "activity");
            Intrinsics.checkNotNullParameter(viewModel, "viewModel");
            DisplayMetrics displayMetrics = new DisplayMetrics();
            activity.getWindowManager().getDefaultDisplay().getMetrics(displayMetrics);
            int i2 = displayMetrics.widthPixels;
            ChooseMultiLinksDialog chooseMultiLinksDialog = new ChooseMultiLinksDialog(activity, viewModel, i2, i2);
            chooseMultiLinksDialog.init();
            Window window = chooseMultiLinksDialog.getWindow();
            if (window != null && (findViewById = window.findViewById(R.id.design_bottom_sheet)) != null) {
                findViewById.setBackgroundResource(android.R.color.transparent);
            }
            return chooseMultiLinksDialog;
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public ChooseMultiLinksDialog(@NotNull Activity context, @NotNull MovieDetailsViewModel viewModel, int i2, int i3) {
        super(context, i2, i3, R.style.TransBottomSheetDialogStyle);
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(viewModel, "viewModel");
        this.context = context;
        this.mViewModel = viewModel;
        this.contentView = LazyKt__LazyJVMKt.lazy(new Function0<View>() { // from class: com.jbzd.media.movecartoons.ui.dialog.ChooseMultiLinksDialog$contentView$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            public final View invoke() {
                Activity activity;
                activity = ChooseMultiLinksDialog.this.context;
                return LayoutInflater.from(activity).inflate(R.layout.dialog_multilinks_choose, (ViewGroup) null);
            }
        });
        this.outside_view = LazyKt__LazyJVMKt.lazy(new Function0<View>() { // from class: com.jbzd.media.movecartoons.ui.dialog.ChooseMultiLinksDialog$outside_view$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final View invoke() {
                View contentView;
                contentView = ChooseMultiLinksDialog.this.getContentView();
                View findViewById = contentView.findViewById(R.id.outside_view);
                Objects.requireNonNull(findViewById, "null cannot be cast to non-null type android.view.View");
                return findViewById;
            }
        });
        this.iv_dismiss = LazyKt__LazyJVMKt.lazy(new Function0<ImageView>() { // from class: com.jbzd.media.movecartoons.ui.dialog.ChooseMultiLinksDialog$iv_dismiss$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final ImageView invoke() {
                View contentView;
                contentView = ChooseMultiLinksDialog.this.getContentView();
                View findViewById = contentView.findViewById(R.id.iv_dismiss);
                Objects.requireNonNull(findViewById, "null cannot be cast to non-null type android.widget.ImageView");
                return (ImageView) findViewById;
            }
        });
        this.rv_multilinks_dialog = LazyKt__LazyJVMKt.lazy(new Function0<RecyclerView>() { // from class: com.jbzd.media.movecartoons.ui.dialog.ChooseMultiLinksDialog$rv_multilinks_dialog$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final RecyclerView invoke() {
                View contentView;
                contentView = ChooseMultiLinksDialog.this.getContentView();
                View findViewById = contentView.findViewById(R.id.rv_multilinks_dialog);
                Objects.requireNonNull(findViewById, "null cannot be cast to non-null type androidx.recyclerview.widget.RecyclerView");
                return (RecyclerView) findViewById;
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final View getContentView() {
        return (View) this.contentView.getValue();
    }

    private final ImageView getIv_dismiss() {
        return (ImageView) this.iv_dismiss.getValue();
    }

    private final View getOutside_view() {
        return (View) this.outside_view.getValue();
    }

    private final RecyclerView getRv_multilinks_dialog() {
        return (RecyclerView) this.rv_multilinks_dialog.getValue();
    }

    private final void initDefaultShow() {
        C2354n.m2374A(getIv_dismiss(), 0L, new Function1<ImageView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.ChooseMultiLinksDialog$initDefaultShow$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ImageView imageView) {
                invoke2(imageView);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull ImageView it) {
                Intrinsics.checkNotNullParameter(it, "it");
                ChooseMultiLinksDialog.this.dismiss();
            }
        }, 1);
        C2354n.m2374A(getOutside_view(), 0L, new Function1<View, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.ChooseMultiLinksDialog$initDefaultShow$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(View view) {
                invoke2(view);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull View it) {
                Intrinsics.checkNotNullParameter(it, "it");
                ChooseMultiLinksDialog.this.dismiss();
            }
        }, 1);
        RecyclerView rv_multilinks_dialog = getRv_multilinks_dialog();
        C4195m.m4821n0(rv_multilinks_dialog, 6, 0, false, false, 14);
        C4195m.m4784Q(rv_multilinks_dialog, C4195m.m4785R(10.0f), DividerOrientation.GRID);
        C4195m.m4774J0(rv_multilinks_dialog, new Function2<BindingAdapter, RecyclerView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.ChooseMultiLinksDialog$initDefaultShow$3
            {
                super(2);
            }

            @Override // kotlin.jvm.functions.Function2
            public /* bridge */ /* synthetic */ Unit invoke(BindingAdapter bindingAdapter, RecyclerView recyclerView) {
                invoke2(bindingAdapter, recyclerView);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull final BindingAdapter bindingAdapter, @NotNull RecyclerView recyclerView) {
                boolean m616f0 = C1499a.m616f0(bindingAdapter, "$this$setup", recyclerView, "it", VideoDetailBean.MultiLinks.class);
                final int i2 = R.layout.item_movie_morelink;
                if (m616f0) {
                    bindingAdapter.f8910l.put(Reflection.typeOf(VideoDetailBean.MultiLinks.class), new Function2<Object, Integer, Integer>() { // from class: com.jbzd.media.movecartoons.ui.dialog.ChooseMultiLinksDialog$initDefaultShow$3$invoke$$inlined$addType$1
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
                    bindingAdapter.f8909k.put(Reflection.typeOf(VideoDetailBean.MultiLinks.class), new Function2<Object, Integer, Integer>() { // from class: com.jbzd.media.movecartoons.ui.dialog.ChooseMultiLinksDialog$initDefaultShow$3$invoke$$inlined$addType$2
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
                bindingAdapter.m3940r(true);
                bindingAdapter.m3935l(new Function1<BindingAdapter.BindingViewHolder, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.ChooseMultiLinksDialog$initDefaultShow$3.1
                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(BindingAdapter.BindingViewHolder bindingViewHolder) {
                        invoke2(bindingViewHolder);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@NotNull BindingAdapter.BindingViewHolder onBind) {
                        Intrinsics.checkNotNullParameter(onBind, "$this$onBind");
                        VideoDetailBean.MultiLinks multiLinks = (VideoDetailBean.MultiLinks) onBind.m3942b();
                        ((TextView) onBind.m3941a(R.id.tv_morelink_name)).setText(multiLinks.name);
                        ((TextView) onBind.m3941a(R.id.tv_morelink_name)).setSelected(multiLinks.is_select.equals("y"));
                    }
                });
                bindingAdapter.m3937n(new int[]{R.id.ll_item_multilink}, new Function2<BindingAdapter.BindingViewHolder, Integer, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.ChooseMultiLinksDialog$initDefaultShow$3.2
                    {
                        super(2);
                    }

                    @Override // kotlin.jvm.functions.Function2
                    public /* bridge */ /* synthetic */ Unit invoke(BindingAdapter.BindingViewHolder bindingViewHolder, Integer num) {
                        invoke(bindingViewHolder, num.intValue());
                        return Unit.INSTANCE;
                    }

                    public final void invoke(@NotNull BindingAdapter.BindingViewHolder onClick, int i3) {
                        Intrinsics.checkNotNullParameter(onClick, "$this$onClick");
                        if (((VideoDetailBean.MultiLinks) onClick.m3942b()).is_select.equals("y")) {
                            return;
                        }
                        BindingAdapter.this.m3938o(onClick.getLayoutPosition(), true);
                        BindingAdapter.this.notifyItemChanged(onClick.getPosition());
                    }
                });
                final ChooseMultiLinksDialog chooseMultiLinksDialog = ChooseMultiLinksDialog.this;
                bindingAdapter.m3936m(new Function3<Integer, Boolean, Boolean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.ChooseMultiLinksDialog$initDefaultShow$3.3
                    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                    {
                        super(3);
                    }

                    @Override // kotlin.jvm.functions.Function3
                    public /* bridge */ /* synthetic */ Unit invoke(Integer num, Boolean bool, Boolean bool2) {
                        invoke(num.intValue(), bool.booleanValue(), bool2.booleanValue());
                        return Unit.INSTANCE;
                    }

                    public final void invoke(int i3, boolean z, boolean z2) {
                        VideoDetailBean.MultiLinks multiLinks = (VideoDetailBean.MultiLinks) BindingAdapter.this.m3930g(i3);
                        int i4 = 0;
                        for (Object obj : chooseMultiLinksDialog.getMulti_links()) {
                            int i5 = i4 + 1;
                            if (i4 < 0) {
                                CollectionsKt__CollectionsKt.throwIndexOverflow();
                            }
                            VideoDetailBean.MultiLinks multiLinks2 = (VideoDetailBean.MultiLinks) obj;
                            if (Intrinsics.areEqual(multiLinks.f9994id, multiLinks2.f9994id)) {
                                multiLinks2.is_select = "y";
                            } else {
                                multiLinks2.is_select = "n";
                            }
                            i4 = i5;
                        }
                        BindingAdapter.this.notifyItemChanged(i3);
                        chooseMultiLinksDialog.getMViewModel().getLinkIdMulti().setValue(multiLinks.f9994id);
                        chooseMultiLinksDialog.dismiss();
                    }
                });
            }
        });
    }

    @Override // androidx.appcompat.app.AppCompatDialog, android.app.Dialog, android.content.DialogInterface
    public void dismiss() {
        View currentFocus = getCurrentFocus();
        if (currentFocus instanceof EditText) {
            C2861e.m3306d(currentFocus);
        }
        super.dismiss();
    }

    @NotNull
    public final MovieDetailsViewModel getMViewModel() {
        return this.mViewModel;
    }

    @NotNull
    public final List<VideoDetailBean.MultiLinks> getMulti_links() {
        List list = this.multi_links;
        if (list != null) {
            return list;
        }
        Intrinsics.throwUninitializedPropertyAccessException("multi_links");
        throw null;
    }

    public final void init() {
        setContentView(getContentView());
        initDefaultShow();
    }

    public final void setLinksData(@NotNull List<? extends VideoDetailBean.MultiLinks> multilinks) {
        Intrinsics.checkNotNullParameter(multilinks, "multilinks");
        setMulti_links(multilinks);
        getRv_multilinks_dialog();
        C4195m.m4793Z(getRv_multilinks_dialog()).m3939q(CollectionsKt___CollectionsKt.toMutableList((Collection) multilinks));
    }

    public final void setMViewModel(@NotNull MovieDetailsViewModel movieDetailsViewModel) {
        Intrinsics.checkNotNullParameter(movieDetailsViewModel, "<set-?>");
        this.mViewModel = movieDetailsViewModel;
    }

    public final void setMulti_links(@NotNull List<? extends VideoDetailBean.MultiLinks> list) {
        Intrinsics.checkNotNullParameter(list, "<set-?>");
        this.multi_links = list;
    }
}
